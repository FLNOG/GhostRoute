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
const uwpDiscovery  = require('./vpn/uwp-discovery');
const { validateRouteRule, classifyRisk, migrateOldItem } = require('./vpn/app-model');
const {
  canonicalId, createRefreshDeduplicator, migrateOldConfig,
  resolveAppsFromCatalog, resolveSelectionWithRefresh, serializeForSave,
  isValidId, updateCatalogInPlace, removeManualFromConfig,
  validateResolvedSelection, normalizeSelectedIds,
} = require('./catalog-utils');
const { createShutdownController } = require('./shutdown-controller');

// ── Catálogo autoritativo ────────────────────────────────────────────────
// A única fonte de verdade para routeRule, launchTarget, compatibility, risk.
// Populado por apps:list. Renderer e settings.json NUNCA são autoridade.
let appCatalog = new Map(); // id → CanonicalApp

function updateAppCatalog(apps) {
  // Usa updateCatalogInPlace: muta o mesmo Map, preservando referências externas
  updateCatalogInPlace(appCatalog, apps);
}

// Refresh deduplicado: múltiplas chamadas concorrentes compartilham a mesma operação
const refreshCatalogNow = createRefreshDeduplicator(async () => {
  const config = loadConfig();
  const [desktopApps, uwpApps, runningPaths] = await Promise.all([
    installedApps.discoverInstalledApps(),
    uwpDiscovery.discoverUwpApps(),
    installedApps.runningExecutablePaths(),
  ]);
  const markRunning = a => ({
    ...a,
    running:      !!(a.path && runningPaths.has(a.path.toLowerCase())),
    runningState: !a.path ? 'unknown' : (runningPaths.has(a.path.toLowerCase()) ? 'running' : 'stopped'),
  });
  const allApps = [...desktopApps.map(markRunning), ...uwpApps.map(markRunning)];

  // Reidratar itens manuais salvos
  for (const manual of (config.manualApps || [])) {
    if (!manual.path || allApps.find(a => a.id === manual.id)) continue;
    const normalized = installedApps.normalizeItem(manual);
    if (normalized) {
      const canonical = buildManualCanonical(normalized);
      allApps.push(markRunning(canonical));
    } else {
      allApps.push({
        id: manual.id, name: manual.name, path: manual.path,
        kind: 'desktop', source: 'manual',
        unavailable: true, unavailableReason: 'Arquivo não encontrado',
        compatibility: 'unsupported', risk: { level: 'none', label: '' },
        routeRule: '', running: false, runningState: 'unknown',
      });
    }
  }
  updateAppCatalog(allApps);
});

function buildManualCanonical(normalized) {
  const routeRule = validateRouteRule(normalized.path) || '';
  return {
    ...normalized,
    kind: 'desktop', source: 'manual',
    routeRule, launchTarget: normalized.path,
    launchArgs: [], workingDirectory: '',
    packageFamilyName: '', appUserModelId: '', installRoot: '',
    risk: installedApps.classifyAppRisk(normalized),
    compatibility: routeRule ? 'supported' : 'unsupported',
    isLauncher: false, launcherNote: '',
    running: false, runningState: 'unknown',
  };
}
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
    const { selectedAppIds, manualApps } = migrateOldConfig(saved);
    const merged = {
      ...defaultConfig(),
      ...saved,
      wireGuardConfigPath: securePath,
      selectiveConfigPath: String(saved.selectiveConfigPath || defaultConfig().selectiveConfigPath),
      discordPath: String(saved.discordPath || defaultConfig().discordPath),
      selectedAppIds,
      manualApps,
    };
    const identity = identityManager.load(app.getPath('userData'));
    return { ...merged, selectiveConfigReady: identity?.status === 'active' || Boolean(merged.selectiveConfigPath && fs.existsSync(merged.selectiveConfigPath)) };
  } catch {
    const defaults = defaultConfig();
    const identity = identityManager.load(app.getPath('userData'));
    return { ...defaults, selectiveConfigReady: identity?.status === 'active' || Boolean(defaults.selectiveConfigPath && fs.existsSync(defaults.selectiveConfigPath)), selectedAppIds: [], manualApps: [] };
  }
}

function saveConfig(config) {
  const safe = {
    wireGuardConfigPath: String(config.wireGuardConfigPath || ''),
    selectiveConfigPath: String(config.selectiveConfigPath || ''),
    discordPath: String(config.discordPath || ''),
    selectedAppIds: Array.isArray(config.selectedAppIds) ? config.selectedAppIds : [],
    manualApps: Array.isArray(config.manualApps)
      ? config.manualApps.map(a => ({ id: a.id, name: a.name, path: a.path })).filter(a => a.id && a.path)
      : [],
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
  // Descobre desktop, UWP e processos em paralelo + reidrata manuais
  await refreshCatalogNow();

  const config = loadConfig();

  // Determinar seleção persistida
  const selectedIds = new Set(config.selectedAppIds || []);

  // Construir lista final com icon e seleção
  const allItems = [...appCatalog.values()].filter((v, i, a) => a.indexOf(v) === i); // unique values
  return Promise.all(allItems.map(async item => {
    const isSelected = selectedIds.has(item.id);
    if (item.kind === 'uwp') return { ...item, icon: '', selected: isSelected };
    try {
      const icon = await app.getFileIcon(item.path, { size: 'small' });
      return { ...item, icon: icon.toDataURL(), selected: isSelected };
    } catch {
      return { ...item, icon: '', selected: isSelected };
    }
  }));
});

ipcMain.handle('apps:add-manual', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Adicionar aplicativo ao GhostRoute', properties: ['openFile'],
    filters: [{ name: 'Aplicativo Windows', extensions: ['exe'] }]
  });
  if (result.canceled) return null;
  const filePath = result.filePaths[0];
  const normalized = installedApps.normalizeItem({ path: filePath, name: path.basename(filePath, '.exe'), source: 'manual' });
  if (!normalized) return null;

  // Verificar risco — anticheat nunca é aceito como manual
  const risk = installedApps.classifyAppRisk(normalized);
  if (risk.level === 'blocked') {
    throw new Error(`${normalized.name} é um anticheat e não pode ser adicionado.`);
  }

  // Construir item canônico completo
  const canonical = buildManualCanonical(normalized);

  // Inserir no catálogo imediatamente
  appCatalog.set(canonical.id, canonical);
  if (canonical.appUserModelId) appCatalog.set(canonical.appUserModelId.toLowerCase(), canonical);

  // Persistir item manual
  const config = loadConfig();
  const manualApps = config.manualApps || [];
  if (!manualApps.find(a => a.id === canonical.id)) {
    manualApps.push({ id: canonical.id, name: canonical.name, path: canonical.path });
    saveConfig({ ...config, manualApps });
  }

  return { ...canonical, icon: '' };
});

ipcMain.handle('apps:save-selection', (_event, rawIds) => {
  guardShutdown('apps:save-selection');
  const config = loadConfig();
  const knownManualIds = (config.manualApps || []).map(a => a.id).filter(isValidId);
  // normalizeSelectedIds: trim, deduplicado, valida contra catálogo + manuais conhecidos
  const ids = normalizeSelectedIds(rawIds, appCatalog, knownManualIds);
  saveConfig({ ...config, selectedAppIds: ids });
  return ids;
});

ipcMain.handle('apps:remove-manual', (_event, rawId) => {
  guardShutdown('apps:remove-manual');
  if (!isValidId(rawId)) throw new Error('ID inválido para remoção.');
  const id = String(rawId).trim();

  const config = loadConfig();
  const { config: newConfig, wasManual } = removeManualFromConfig(config, id);
  if (!wasManual) {
    // ID não é manual — não modifica config nem catálogo; idempotente
    return { removed: false };
  }
  // Salva configuração primeiro; só então remove do catálogo em memória
  saveConfig(newConfig);
  appCatalog.delete(id);
  return { removed: true };
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

  // Resolver apps via catálogo com refresh se necessário
  // (nunca descarta parcial — ou todos os IDs resolvem ou rejeita tudo)
  const rawIds = Array.isArray(options?.apps)
    ? options.apps.map(item => typeof item === 'string' ? item : canonicalId(item)).filter(Boolean)
    : [];
  const resolvedApps = await resolveSelectionWithRefresh(rawIds, appCatalog, refreshCatalogNow);
  if (resolvedApps.length === 0 && rawIds.length > 0) {
    throw new Error('Nenhum aplicativo selecionado foi encontrado no catálogo atual. Recarregue a lista.');
  }

  // Validar que todos os itens resolvidos são selecionáveis
  // (indisponíveis, incompatíveis ou bloqueados NUNCA iniciam parcialmente)
  validateResolvedSelection(resolvedApps);

  let sessionConfig = '';
  try {
    sessionConfig = identity?.status === 'active'
      ? await identityManager.materializeConfig(app.getPath('userData'))
      : localConfig.selectiveConfigPath;
    return await selective.start({
      sourceConfigPath: sessionConfig,
      apps: resolvedApps,
      runtimeDirectory: app.getPath('userData'),
      launchApps: options?.launchApps !== false
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
