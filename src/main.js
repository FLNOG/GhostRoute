'use strict';

const { app, BrowserWindow, clipboard, dialog, ipcMain, session,
  Tray, Menu, Notification, nativeImage } = require('electron');
const fs   = require('node:fs');
const path = require('node:path');
const wireguard     = require('./vpn/wireguard-controller');
const diagnostics   = require('./vpn/network-diagnostics');
const selective     = require('./vpn/selective-controller');
const installedApps = require('./vpn/installed-apps');
const identityManager = require('./vpn/identity-manager');
const { createShutdownController } = require('./shutdown-controller');
const { createCleanupFn }          = require('./app-cleanup');
const { selectiveStateForMenu }    = require('./tray-menu-state');

// ── Estado de módulo ──────────────────────────────────────────────────────

let mainWindow = null;
let tray       = null;

// Impede que before-quit chame cleanup novamente após quitFn() já ter chamado app.quit().
let allowedToQuit = false;

// Previne cliques concorrentes em "Desconectar VPN" da bandeja.
let trayDisconnecting = false;

const GHOST_ICON_PATH = path.join(__dirname, 'assets', 'ghostroute-ghost.png');

// ── Tray ──────────────────────────────────────────────────────────────────

function buildTrayMenu() {
  const selState = selective.status().state;
  const { statusLabel, disconnectEnabled } = selectiveStateForMenu(selState);
  const isShuttingDown = shutdownController.isShuttingDown() || shutdownController.isDone();

  return Menu.buildFromTemplate([
    {
      label: 'Abrir GhostRoute',
      click: () => {
        if (mainWindow && !mainWindow.isDestroyed()) { mainWindow.show(); mainWindow.focus(); }
      }
    },
    { type: 'separator' },
    { label: statusLabel, enabled: false },
    {
      label: trayDisconnecting ? 'Desconectando\u2026' : 'Desconectar VPN',
      enabled: disconnectEnabled && !isShuttingDown && !trayDisconnecting,
      click: () => {
        if (trayDisconnecting || isShuttingDown) return;
        trayDisconnecting = true;
        updateTrayMenu();
        selective.stop('Desconectado pelo menu da bandeja.')
          .then(() => {
            trayDisconnecting = false;
            updateTrayMenu();
          })
          .catch(err => {
            trayDisconnecting = false;
            updateTrayMenu();
            const msg = `Falha ao desconectar VPN: ${String(err?.message || err)}`;
            if (mainWindow && !mainWindow.isDestroyed() && !mainWindow.webContents.isDestroyed()) {
              mainWindow.webContents.send('app:shutdown-failed', msg);
            }
            if (mainWindow && !mainWindow.isDestroyed()) {
              mainWindow.show();
              mainWindow.focus();
            }
          });
      }
    },
    { type: 'separator' },
    {
      label: 'Sair e encerrar tudo',
      enabled: !isShuttingDown,
      click: () => {
        shutdownController.requestShutdown('menu').catch(() => {});
      }
    }
  ]);
}

function createTray() {
  let icon;
  try { icon = nativeImage.createFromPath(GHOST_ICON_PATH).resize({ height: 20 }); }
  catch { icon = nativeImage.createEmpty(); }
  tray = new Tray(icon);
  tray.setToolTip('GhostRoute');
  tray.setContextMenu(buildTrayMenu());
  tray.on('double-click', () => {
    if (mainWindow && !mainWindow.isDestroyed()) { mainWindow.show(); mainWindow.focus(); }
  });
}

function updateTrayMenu() {
  if (tray && !tray.isDestroyed()) tray.setContextMenu(buildTrayMenu());
}

// ── Shutdown Controller ───────────────────────────────────────────────────

const cleanupFn = createCleanupFn({
  getSelectiveStatus:   () => selective.status(),
  stopSelective:        (reason) => selective.stop(reason),
  getFullTunnelPath:    () => loadConfig().wireGuardConfigPath,
  getFullTunnelStatus:  (p) => wireguard.status(p),
  disconnectFullTunnel: (p) => wireguard.disconnect(p),
  cleanupTempFiles:     () => identityManager.cleanupStaleConfigs(app.getPath('userData'))
});

const shutdownController = createShutdownController({
  cleanupFn,

  quitFn: () => {
    // Define allowedToQuit ANTES de app.quit() para que before-quit não previna a saída.
    allowedToQuit = true;
    app.quit();
  },

  showWindowFn: () => {
    if (mainWindow && !mainWindow.isDestroyed()) { mainWindow.show(); mainWindow.focus(); }
  },

  showErrorFn: (msg) => {
    const safe = String(msg || 'Ocorreu um erro ao encerrar.');
    if (mainWindow && !mainWindow.isDestroyed() && !mainWindow.webContents.isDestroyed()) {
      mainWindow.webContents.send('app:shutdown-failed', safe);
    }
  },

  destroyTrayFn: () => {
    if (tray && !tray.isDestroyed()) { tray.destroy(); tray = null; }
  }
});

// ── Guard de shutdown para handlers IPC mutáveis ─────────────────────────
// O cleanup interno chama selective.stop() / wireguard.disconnect() DIRETAMENTE
// (não via IPC), portanto não é afetado por este bloqueio.

function guardShutdown(handlerName) {
  if (shutdownController.isShuttingDown() || shutdownController.isDone()) {
    throw new Error(`GhostRoute está encerrando. (${handlerName})`);
  }
}

// ── Config ────────────────────────────────────────────────────────────────

function configPath() {
  return path.join(app.getPath('userData'), 'settings.json');
}

function defaultConfig() {
  const localConfig = path.join(app.getAppPath(), 'wireguard', 'ghostroute-teste.conf');
  const discordExecutable = installedApps.findDiscordExecutable();
  return {
    wireGuardConfigPath: '',
    selectiveConfigPath: fs.existsSync(localConfig) ? localConfig : '',
    discordPath: fs.existsSync(discordExecutable) ? discordExecutable : '',
    selectedApps: fs.existsSync(discordExecutable) ? [{ name: 'Discord', path: discordExecutable }] : []
  };
}

function loadConfig() {
  try {
    const saved = JSON.parse(fs.readFileSync(configPath(), 'utf8'));
    const storedPath = String(saved.wireGuardConfigPath || '');
    const securePath = storedPath.toLowerCase().endsWith('.conf')
      ? wireguard.secureConfigPath(storedPath)
      : storedPath;
    const merged = {
      ...defaultConfig(),
      ...saved,
      wireGuardConfigPath: securePath,
      selectiveConfigPath: String(saved.selectiveConfigPath || defaultConfig().selectiveConfigPath),
      discordPath: String(saved.discordPath || defaultConfig().discordPath),
      selectedApps: Array.isArray(saved.selectedApps) && saved.selectedApps.length
        ? saved.selectedApps.map(installedApps.normalizeItem).filter(Boolean)
        : defaultConfig().selectedApps
    };
    const identity = identityManager.load(app.getPath('userData'));
    return { ...merged, selectiveConfigReady: identity?.status === 'active' || Boolean(merged.selectiveConfigPath && fs.existsSync(merged.selectiveConfigPath)) };
  } catch {
    const defaults = defaultConfig();
    const identity = identityManager.load(app.getPath('userData'));
    return { ...defaults, selectiveConfigReady: identity?.status === 'active' || Boolean(defaults.selectiveConfigPath && fs.existsSync(defaults.selectiveConfigPath)) };
  }
}

function saveConfig(config) {
  const safe = {
    wireGuardConfigPath: String(config.wireGuardConfigPath || ''),
    selectiveConfigPath: String(config.selectiveConfigPath || ''),
    discordPath: String(config.discordPath || ''),
    selectedApps: Array.isArray(config.selectedApps)
      ? config.selectedApps.map(installedApps.normalizeItem).filter(Boolean).map(({ name, path: executablePath }) => ({ name, path: executablePath }))
      : []
  };
  fs.mkdirSync(path.dirname(configPath()), { recursive: true });
  fs.writeFileSync(configPath(), JSON.stringify(safe, null, 2), { mode: 0o600 });
}

// ── Janela principal ──────────────────────────────────────────────────────

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 900, height: 720, minWidth: 760, minHeight: 620,
    backgroundColor: '#09060e', title: 'GhostRoute', icon: GHOST_ICON_PATH,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });
  mainWindow.removeMenu();

  // X da janela → esconde na bandeja, não destrói
  mainWindow.on('close', (event) => {
    if (shutdownController.isAllowedToClose()) return;
    event.preventDefault();
    mainWindow.hide();
    if (shutdownController.noteFirstHide() && Notification.isSupported()) {
      new Notification({
        title: 'GhostRoute',
        body: 'GhostRoute continua ativo na bandeja. Use \u201cSair e encerrar tudo\u201d para finalizar a VPN.'
      }).show();
    }
  });

  // ── Integração com shutdown/logoff do Windows ─────────────────────────
  // Nota: before-quit NÃO é emitido no Windows durante shutdown/restart/logoff.
  // Usamos query-session-end e session-end como melhor esforço.
  // O Windows PODE encerrar o processo antes que operações assíncronas terminem.
  // Não há garantia absoluta de cleanup durante desligamento do sistema.

  mainWindow.on('query-session-end', () => {
    // Windows pergunta se podemos encerrar a sessão.
    // Inicia cleanup de melhor esforço; não bloqueia indefinidamente o desligamento.
    // NÃO mostra diálogos nem restaura janela neste contexto.
    if (!shutdownController.isShuttingDown() && !shutdownController.isDone()) {
      shutdownController.requestShutdown('os').catch(() => {});
    }
    // Não retornar false: permitir que o Windows prossiga com o shutdown.
  });

  mainWindow.on('session-end', () => {
    // Sessão definitivamente encerrando. Apenas operações síncronas seguras.
    // Windows pode matar o processo a qualquer momento após este evento.
    allowedToQuit = true; // evita que before-quit bloqueie a saída residual
    // Sem async, sem diálogos, sem restauração de janela.
  });

  mainWindow.loadFile(path.join(__dirname, 'index.html'));
}

// ── Ciclo de vida do app ──────────────────────────────────────────────────

app.whenReady().then(() => {
  identityManager.cleanupStaleConfigs(app.getPath('userData'));
  if (process.platform === 'win32') app.setAppUserModelId(app.getName());

  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': ["default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'"]
      }
    });
  });

  createWindow();
  createTray();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

// Bandeja mantém o app vivo. Não chamar app.quit() aqui.
app.on('window-all-closed', () => {
  if (process.platform === 'darwin') app.quit();
});

app.on('before-quit', (event) => {
  if (allowedToQuit) return;
  event.preventDefault();
  shutdownController.requestShutdown('os').then(result => {
    if (!result.success) {
      // SO está encerrando — força saída mesmo após falha.
      // Justificativa para app.exit(): não podemos bloquear shutdown do SO indefinidamente.
      allowedToQuit = true;
      app.exit(0);
    }
  });
});

// ── Listener de estado seletivo → atualiza tray + renderer ───────────────

selective.setStatusListener(status => {
  if (mainWindow && !mainWindow.isDestroyed() && !mainWindow.webContents.isDestroyed()) {
    mainWindow.webContents.send('selective:status-changed', status);
  }
  updateTrayMenu();
});

// ── Handlers IPC ─────────────────────────────────────────────────────────

ipcMain.handle('config:load', () => loadConfig());

ipcMain.handle('vpn:select-config', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Selecione a configuração WireGuard',
    properties: ['openFile'],
    filters: [{ name: 'Configuração WireGuard', extensions: ['conf'] }]
  });
  if (result.canceled) return null;
  const selected = result.filePaths[0];
  wireguard.validateConfigPath(selected);
  const securePath = wireguard.secureConfigPath(selected);
  saveConfig({ ...loadConfig(), wireGuardConfigPath: securePath });
  return securePath;
});

ipcMain.handle('vpn:status', (_event, rawPath) => wireguard.status(String(rawPath || '')));

ipcMain.handle('vpn:connect', async (_event, rawPath) => {
  guardShutdown('vpn:connect');
  if (selective.status().state !== 'stopped') throw new Error('Encerre ou repare o modo seletivo antes de ativar a VPN completa.');
  return wireguard.connect(String(rawPath || ''));
});

ipcMain.handle('vpn:disconnect', async (_event, rawPath) => {
  guardShutdown('vpn:disconnect');
  return wireguard.disconnect(String(rawPath || ''));
});

ipcMain.handle('vpn:diagnostics', () => diagnostics.runDiagnostics());

ipcMain.handle('apps:list', async () => {
  const discovered = await installedApps.discoverInstalledApps();
  const selected = loadConfig().selectedApps || [];
  const combined = [...discovered, ...selected];
  const seen = new Set();
  const unique = combined.filter(item => {
    const id = item.path.toLowerCase();
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
  return Promise.all(unique.map(async item => {
    try {
      const icon = await app.getFileIcon(item.path, { size: 'small' });
      return { ...item, icon: icon.toDataURL() };
    } catch {
      return { ...item, icon: '' };
    }
  }));
});

ipcMain.handle('apps:add-manual', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Adicionar aplicativo ao GhostRoute', properties: ['openFile'],
    filters: [{ name: 'Aplicativo Windows', extensions: ['exe'] }]
  });
  if (result.canceled) return null;
  return installedApps.normalizeItem({ path: result.filePaths[0], name: path.basename(result.filePaths[0], '.exe') });
});

ipcMain.handle('apps:save-selection', (_event, rawApps) => {
  guardShutdown('apps:save-selection');
  const selectedApps = Array.isArray(rawApps) ? rawApps.map(installedApps.normalizeItem).filter(Boolean) : [];
  saveConfig({ ...loadConfig(), selectedApps });
  return selectedApps;
});

ipcMain.handle('identity:status', () => identityManager.publicIdentity(identityManager.load(app.getPath('userData'))));

ipcMain.handle('identity:generate', async () => {
  guardShutdown('identity:generate');
  return identityManager.generate(app.getPath('userData'));
});

ipcMain.handle('identity:activate', (_event, address) => {
  guardShutdown('identity:activate');
  return identityManager.activate(app.getPath('userData'), address);
});

ipcMain.handle('identity:copy-request', () => {
  const identity = identityManager.load(app.getPath('userData'));
  const request = identityManager.requestText(identity);
  clipboard.writeText(request);
  return true;
});

ipcMain.handle('selective:status', () => selective.status());

ipcMain.handle('selective:start', async (_event, options) => {
  guardShutdown('selective:start');
  const fullStatus = await wireguard.status(String(options?.fullTunnelConfigPath || ''));
  if (fullStatus.state !== 'disconnected') throw new Error('Desconecte a VPN completa antes de iniciar o modo seletivo.');
  const localConfig = loadConfig();
  if (!localConfig.selectiveConfigReady) throw new Error('A identidade VPN deste computador ainda não foi provisionada.');
  const identity = identityManager.load(app.getPath('userData'));
  let sessionConfig = '';
  try {
    sessionConfig = identity?.status === 'active'
      ? await identityManager.materializeConfig(app.getPath('userData'))
      : localConfig.selectiveConfigPath;
    return await selective.start({
      sourceConfigPath: sessionConfig,
      apps: Array.isArray(options?.apps) ? options.apps : [],
      runtimeDirectory: app.getPath('userData')
    });
  } finally {
    if (identity?.status === 'active') identityManager.removeMaterializedConfig(sessionConfig);
  }
});

ipcMain.handle('selective:stop', () => {
  guardShutdown('selective:stop');
  return selective.stop();
});

ipcMain.handle('app:request-quit', () => {
  return shutdownController.requestShutdown('menu');
});
