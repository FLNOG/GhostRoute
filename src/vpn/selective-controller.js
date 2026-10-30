const { execFile, spawn, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { createOperationGuard } = require('./operation-guard');

const SERVER_IP = '193.122.219.14';
const WIRESOCK_CLI = 'C:\\Program Files\\WireSock Secure Connect\\command-line\\wiresock-connect-cli.exe';
const WIRESOCK_PROFILE = 'wiresock.generated';
const WIRESOCK_APP_SERVICE = 'WireSockAppService';
const WIRESOCK_CONNECT_SERVICE = 'WireSockConnectService';

let selectiveActive = false;
let launchedProcesses = [];
let stopping = false;
const operationGuard = createOperationGuard();
let onStatusChange = () => {};
let pendingCleanupReason = null; // corrida pós-spawn: cleanup adiado enquanto guard está ocupado
let stopPromise = null;          // stop() compartilhado: chamadas concorrentes aguardam a mesma operação

function generatedConfigPath(runtimeDirectory) {
  const directory = runtimeDirectory || path.join(process.env.APPDATA || path.resolve(__dirname, '..', '..'), 'ghostroute');
  return path.join(directory, 'wiresock.generated.conf');
}

function validateFile(filePath, extension, label) {
  if (typeof filePath !== 'string' || !path.isAbsolute(filePath) || !fs.existsSync(filePath)) {
    throw new Error(`${label} não encontrado.`);
  }
  if (extension && path.extname(filePath).toLowerCase() !== extension) {
    throw new Error(`${label} precisa ser um arquivo ${extension}.`);
  }
}

function wiresockExecutable() {
  if (!fs.existsSync(WIRESOCK_CLI)) {
    throw new Error('WireSock Secure Connect não foi encontrado. Instale o cliente oficial completo e reinicie o GhostRoute.');
  }
  return WIRESOCK_CLI;
}

function resolveDiscordExecutable(selectedPath) {
  const parent = path.dirname(selectedPath);
  if (path.basename(parent).toLowerCase().startsWith('app-')) return selectedPath;
  const basename = path.basename(selectedPath).toLowerCase();
  const discordRoot = parent;
  if (basename !== 'discord.exe' && basename !== 'update.exe') {
    validateFile(selectedPath, '.exe', 'Executável do Discord');
    return selectedPath;
  }
  const candidates = fs.existsSync(discordRoot) ? fs.readdirSync(discordRoot, { withFileTypes: true })
    .filter(entry => entry.isDirectory() && entry.name.toLowerCase().startsWith('app-'))
    .map(entry => path.join(discordRoot, entry.name, 'Discord.exe'))
    .filter(candidate => fs.existsSync(candidate))
    .sort((left, right) => right.localeCompare(left, undefined, { numeric: true })) : [];
  const resolved = candidates[0] || selectedPath;
  validateFile(resolved, '.exe', 'Executável do Discord');
  return resolved;
}

function routingRule(executablePath) {
  const parent = path.dirname(executablePath);
  return path.basename(parent).toLowerCase().startsWith('app-') ? path.dirname(parent) : executablePath;
}

function normalizeApps(apps) {
  if (!Array.isArray(apps) || apps.length === 0) throw new Error('Selecione pelo menos um aplicativo para o túnel.');
  const seen = new Set();
  return apps.map(item => {
    const executable = String(item?.name || '').toLowerCase() === 'discord'
      ? resolveDiscordExecutable(String(item.path))
      : String(item?.path || '');
    if (executable.includes(',')) {
      throw new Error(`${String(item?.name || path.basename(executable))} não pode ser usado porque o caminho contém vírgula.`);
    }
    validateFile(executable, '.exe', `Aplicativo ${String(item?.name || '').trim() || 'selecionado'}`);
    const key = executable.toLowerCase();
    if (seen.has(key)) return null;
    seen.add(key);
    return { name: String(item?.name || path.basename(executable, '.exe')), path: executable };
  }).filter(Boolean);
}

function buildWireSockConfig(sourceConfigPath, apps, runtimeDirectory) {
  validateFile(sourceConfigPath, '.conf', 'Configuração WireGuard seletiva');
  const original = fs.readFileSync(sourceConfigPath, 'utf8');
  if (!/^\s*\[Interface\]\s*$/im.test(original) || !/^\s*\[Peer\]\s*$/im.test(original)) {
    throw new Error('A configuração não contém as seções [Interface] e [Peer].');
  }

  const rules = normalizeApps(apps).map(item => routingRule(item.path));
  const lines = original.replace(/\r\n/g, '\n').split('\n');
  const output = [];
  let section = '';
  let directiveAdded = false;
  const addDirective = () => {
    if (section === 'peer' && !directiveAdded) {
      output.push(`#@ws:AllowedApps = ${rules.join(', ')}`);
      directiveAdded = true;
    }
  };

  for (const line of lines) {
    const sectionMatch = line.match(/^\s*\[([^\]]+)\]\s*$/);
    if (sectionMatch) {
      addDirective();
      section = sectionMatch[1].trim().toLowerCase();
      output.push(line);
      continue;
    }
    if (/^\s*(?:#@ws:)?AllowedApps\s*=/i.test(line)) continue;
    // WireSock applies DNS system-wide. Preserve the resolver used by Windows so
    // non-selected applications remain as close as possible to their normal path.
    if (section === 'interface' && /^\s*DNS\s*=/i.test(line)) continue;
    output.push(line);
  }
  addDirective();

  const destination = generatedConfigPath(runtimeDirectory);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.writeFileSync(destination, `${output.join('\r\n').trim()}\r\n`, { mode: 0o600 });
  return destination;
}

function command(file, args, timeout = 15000) {
  return new Promise((resolve, reject) => {
    execFile(file, args, { windowsHide: true, timeout }, (error, stdout, stderr) => {
      if (error) return reject(new Error(String(stderr || stdout || error.message).trim()));
      resolve(String(stdout).trim());
    });
  });
}

async function isExecutableRunning(executablePath) {
  try {
    const processName = path.basename(executablePath, path.extname(executablePath));
    const script = [
      `$target = [IO.Path]::GetFullPath('${escapePowerShellSingleQuoted(executablePath)}')`,
      `$match = Get-Process -Name '${escapePowerShellSingleQuoted(processName)}' -ErrorAction SilentlyContinue | Where-Object { $_.Path -and ([IO.Path]::GetFullPath($_.Path) -ieq $target) } | Select-Object -First 1`,
      "if ($match) { [Console]::Out.Write('true') } else { [Console]::Out.Write('false') }"
    ].join('; ');
    const output = await command('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encodePowerShell(script)], 5000);
    return output === 'true';
  } catch {
    return false;
  }
}

function killProcessTree(pid) {
  if (!pid) return Promise.resolve();
  return command('taskkill.exe', ['/pid', String(pid), '/t', '/f'], 10000).catch(() => {});
}

function isServiceRunning(serviceName) {
  const result = spawnSync('sc.exe', ['query', serviceName], { windowsHide: true, encoding: 'utf8' });
  return result.status === 0 && /(?:STATE|ESTADO)\s*:\s*4\s+/i.test(String(result.stdout));
}

function hasRunningServices() {
  return isServiceRunning(WIRESOCK_APP_SERVICE) || isServiceRunning(WIRESOCK_CONNECT_SERVICE);
}

function escapePowerShellSingleQuoted(value) {
  return String(value).replaceAll("'", "''");
}

function encodePowerShell(script) {
  return Buffer.from(script, 'utf16le').toString('base64');
}

function addCheckedServiceCommand(lines, command, accepted) {
  lines.push(`${command} | Out-Null`);
  lines.push(`if (@(${accepted.join(', ')}) -notcontains $LASTEXITCODE) { exit $LASTEXITCODE }`);
}

function runElevatedWireSock(steps, serviceAction = '') {
  const cli = wiresockExecutable();
  const innerLines = [];
  if (serviceAction === 'start') {
    addCheckedServiceCommand(innerLines, `sc.exe config '${WIRESOCK_APP_SERVICE}' start= demand`, [0]);
    addCheckedServiceCommand(innerLines, `sc.exe config '${WIRESOCK_CONNECT_SERVICE}' start= demand`, [0]);
    addCheckedServiceCommand(innerLines, `sc.exe start '${WIRESOCK_APP_SERVICE}'`, [0, 1056]);
    innerLines.push('Start-Sleep -Seconds 1');
    addCheckedServiceCommand(innerLines, `sc.exe start '${WIRESOCK_CONNECT_SERVICE}'`, [0, 1056]);
    innerLines.push('Start-Sleep -Seconds 2');
  }
  steps.forEach(step => {
    const args = step.args;
    const quotedArgs = args.map(value => `'${escapePowerShellSingleQuoted(value)}'`).join(' ');
    innerLines.push(`& '${escapePowerShellSingleQuoted(cli)}' ${quotedArgs}`);
    const accepted = (step.accepted || [0]).map(Number).join(', ');
    innerLines.push(`if (@(${accepted}) -notcontains $LASTEXITCODE) { exit $LASTEXITCODE }`);
  });
  if (serviceAction === 'stop') {
    addCheckedServiceCommand(innerLines, `sc.exe stop '${WIRESOCK_CONNECT_SERVICE}'`, [0, 1062]);
    innerLines.push('Start-Sleep -Seconds 1');
    addCheckedServiceCommand(innerLines, `sc.exe stop '${WIRESOCK_APP_SERVICE}'`, [0, 1062]);
    innerLines.push('Start-Sleep -Seconds 2');
  }
  innerLines.push('exit 0');
  const encoded = encodePowerShell(innerLines.join('; '));
  const outer = [
    `$process = Start-Process -FilePath 'powershell.exe'`,
    `-ArgumentList '-NoProfile -NonInteractive -EncodedCommand ${encoded}'`,
    '-Verb RunAs -WindowStyle Hidden -Wait -PassThru;',
    'exit $process.ExitCode'
  ].join(' ');

  return new Promise((resolve, reject) => {
    const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', outer], {
      windowsHide: true,
      stdio: ['ignore', 'ignore', 'pipe']
    });
    let stderr = '';
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', code => {
      if (code === 0) resolve();
      else if (code === 1223) reject(new Error('A solicitação de administrador foi cancelada.'));
      else reject(new Error(stderr.trim() || `O WireSock não aceitou a operação solicitada (código ${code}).`));
    });
  });
}

/**
 * Inicia um processo de forma segura, confirmando via evento 'spawn'.
 *
 * Garante que:
 *  - O listener de 'error' é registrado imediatamente após spawn() retornar.
 *  - A Promise resolve somente após o SO confirmar 'spawn'.
 *  - 'error' antes de 'spawn' rejeita a Promise sem unhandled rejection.
 *  - Listeners temporários são removidos após o desfecho.
 *  - Após 'spawn', um listener permanente captura erros tardios via stop().
 *
 * @param {{ path: string, name: string }} appDef
 * @param {Function|null} [_spawnFn]  Substitui spawn() para testes.
 * @returns {Promise<ChildProcess>}
 */
function spawnAndConfirm(appDef, _spawnFn = null) {
  const spawnFn = _spawnFn || spawn;
  const { path: execPath, name: appName } = appDef;

  return new Promise((resolve, reject) => {
    const child = spawnFn(execPath, [], {
      cwd: path.dirname(execPath), windowsHide: false, detached: false, stdio: 'ignore'
    });

    let settled = false;

    const onError = (err) => {
      if (settled) return;
      settled = true;
      child.removeListener('spawn', onSpawn);
      reject(err);
    };

    const onSpawn = () => {
      if (settled) return;
      settled = true;
      child.removeListener('error', onError);
      // Listener permanente: captura erros de runtime após confirmação do spawn.
      // stop() usa .catch(() => {}) para suprimir rejeições não tratadas.
      child.once('error', postErr => {
        requestStop(`${appName} não pôde ser iniciado: ${postErr.message}`);
      });
      resolve(child);
    };

    child.once('error', onError);
    child.once('spawn', onSpawn);
  });
}

/**
 * Solicita stop() de forma segura.
 * Se o guard estiver ocupado (durante start/stop), registra o cleanup como pendente
 * e o executa logo após a liberação do guard — sem rejeitar nem criar unhandled rejection.
 * Múltiplas chamadas simultâneas preservam somente o primeiro motivo.
 *
 * @param {string} reason
 * @param {{ _stopFn?: Function, _isLocked?: () => boolean }} [_opts={}] Injetáveis para testes.
 */
function requestStop(reason, _opts = {}) {
  const isLocked = _opts._isLocked ? _opts._isLocked() : operationGuard.isLocked();
  if (isLocked) {
    if (pendingCleanupReason === null) pendingCleanupReason = reason;
  } else {
    const fn = _opts._stopFn || stop;
    fn(reason).catch(() => {});
  }
}

/**
 * Executa o cleanup pendente registrado por requestStop(), se houver.
 * Deve ser chamada no finally de start() após releaseOperation().
 * @param {Function|null} [_stopFn=null] Injetável para testes.
 * @returns {boolean} true se um cleanup pendente foi iniciado.
 */
function _processPendingCleanup(_stopFn = null) {
  if (pendingCleanupReason !== null) {
    const reason = pendingCleanupReason;
    pendingCleanupReason = null;
    if (selectiveActive) {
      (_stopFn || stop)(reason).catch(() => {});
      return true;
    }
  }
  return false;
}

/**
 * Para o modo seletivo.
 *
 * Chamadas concorrentes são deduplicadas via stopPromise:
 * se já houver um stop em andamento, retorna a mesma Promise (não um wrapper).
 * A falha chega a todos os chamadores.
 *
 * Função regular (não async) para garantir que `p1 === p2` quando compartilhadas.
 *
 * @param {string} [reason]
 * @param {object} [_opts] Injetáveis para testes (_killFn, _disconnectFn, _hasRunningServicesFn).
 * @returns {Promise}
 */
function stop(reason = 'Modo seletivo encerrado.', _opts = {}) {
  // Chamada concorrente: retorna a mesma instância de Promise.
  if (stopPromise) return stopPromise;

  // Guard pode estar retido por start(). Retorna Promise rejeitada se bloqueado.
  let releaseOperation;
  try {
    releaseOperation = operationGuard.acquire('Aguarde a operação atual do modo seletivo terminar.');
  } catch (err) {
    return Promise.reject(err);
  }

  const killFn        = _opts._killFn        ?? (pid => killProcessTree(pid));
  const disconnectFn  = _opts._disconnectFn  ?? (() => runElevatedWireSock([{ args: ['disconnect'], accepted: [0, 2] }], 'stop'));
  const hasServicesFn = _opts._hasRunningServicesFn ?? hasRunningServices;

  stopPromise = (async () => {
    try {
      const currentProcesses = launchedProcesses;
      launchedProcesses = [];
      await Promise.all(currentProcesses.map(async proc => {
        try { await killFn(proc.pid); } catch {}
      }));
      if (selectiveActive || hasServicesFn()) {
        await disconnectFn();
        selectiveActive = false;
      }
      const result = { state: 'stopped', message: reason };
      try { onStatusChange(result); } catch {}
      return result;
    } finally {
      stopPromise = null;
      releaseOperation();
    }
  })();

  return stopPromise;
}

/**
 * Encerra uma sessão seletiva parcialmente ou totalmente iniciada.
 * Não adquire nem libera o OperationGuard — assume que o chamador já o detém.
 *
 * @param {object}   opts
 * @param {Array}    opts.startedProcesses  Processos já iniciados (objetos com .pid).
 * @param {boolean}  opts.disconnectWireSock  Se true, desconecta WireSock e para serviços.
 * @param {Function|null} opts._killFn       Injetável para testes (substitui killProcessTree).
 * @param {Function|null} opts._disconnectFn Injetável para testes (substitui runElevatedWireSock disconnect).
 * @param {Function|null} opts._notifyFn     Injetável para testes (substitui onStatusChange).
 */
async function cleanupSelectiveSession({
  startedProcesses = [],
  disconnectWireSock = false,
  _killFn = null,
  _disconnectFn = null,
  _notifyFn = null
} = {}) {
  const killFn = _killFn || (pid => killProcessTree(pid));
  const disconnectFn = _disconnectFn || (
    () => runElevatedWireSock([{ args: ['disconnect'], accepted: [0, 2] }], 'stop')
  );

  // Encerra todos os processos já iniciados; erros individuais não impedem os demais.
  // async wrapper normaliza tanto lançamentos síncronos quanto rejeições de Promise,
  // garantindo que uma função injetada que lance sincronamente não quebre o Promise.all.
  await Promise.all(startedProcesses.map(async child => {
    try { await killFn(child.pid); } catch {}
  }));

  // Desconecta WireSock somente se a conexão foi estabelecida.
  if (disconnectWireSock) {
    try { await disconnectFn(); } catch {}
  }

  selectiveActive = false;
  launchedProcesses = [];

  // Notificação opcional — falha não deve deixar o estado inconsistente.
  if (_notifyFn) {
    try { _notifyFn({ state: 'stopped' }); } catch {}
  }
}

async function start({ sourceConfigPath, apps, runtimeDirectory }) {
  if (selectiveActive) throw new Error('O modo seletivo já está ativo.');
  const releaseOperation = operationGuard.acquire('O modo seletivo já está iniciando.');
  let config = '';
  let wireSockConnected = false;
  // Array de ChildProcess acumulado sequencialmente para que o catch
  // consiga encerrar exatamente os processos já iniciados em caso de falha parcial.
  const startedProcesses = [];

  try {
    const selectedApps = normalizeApps(apps);
    const running = [];
    for (const selectedApp of selectedApps) {
      if (await isExecutableRunning(selectedApp.path)) running.push(selectedApp.name);
    }
    if (running.length) {
      throw new Error(`Feche completamente antes de iniciar: ${running.join(', ')}.`);
    }

    wiresockExecutable();
    config = buildWireSockConfig(sourceConfigPath, selectedApps, runtimeDirectory);
    await runElevatedWireSock([
      { args: ['disconnect'], accepted: [0, 2] },
      { args: ['delete', WIRESOCK_PROFILE], accepted: [0, 2] },
      { args: ['import', config] },
      { args: ['connect', WIRESOCK_PROFILE, '-log-level', 'error', '-network-lock', 'disabled', '-exit'] }
    ], 'start');
    wireSockConnected = true;

    // Spawn sequencial com confirmação via evento 'spawn'.
    // spawnAndConfirm registra o listener de 'error' imediatamente após spawn()
    // retornar e aguarda a confirmação do SO via 'spawn' antes de resolver.
    // Somente processos confirmados são inseridos em startedProcesses.
    for (const selectedApp of selectedApps) {
      const child = await spawnAndConfirm(selectedApp);
      startedProcesses.push(child);
    }

    // Só comita o estado depois que todos os spawns foram confirmados.
    selectiveActive = true;
    launchedProcesses = startedProcesses;
    // Listeners de erro permanentes já foram registrados dentro de spawnAndConfirm.

    const result = {
      state: 'running',
      serverIp: SERVER_IP,
      appCount: selectedApps.length,
      engine: 'WireSock Secure Connect'
    };
    // Falha de notificação (ex.: BrowserWindow já destruída) é não-fatal:
    // a sessão já está ativa e deve permanecer assim.
    try { onStatusChange(result); } catch {}
    return result;

  } catch (error) {
    // Limpeza sem liberar/readquirir o guard.
    // startedProcesses contém apenas os processos já criados até o ponto de falha.
    await cleanupSelectiveSession({ startedProcesses, disconnectWireSock: wireSockConnected });
    throw error;
  } finally {
    // Remove o conf temporário em qualquer desfecho; { force: true } é idempotente.
    if (config) try { fs.rmSync(config, { force: true }); } catch {}
    releaseOperation();
    // Executa cleanup adiado de erros pós-spawn ocorridos durante esta operação.
    _processPendingCleanup();
  }
}

function status() {
  const residual = !selectiveActive && hasRunningServices();
  return {
    state: selectiveActive ? 'running' : (operationGuard.isLocked() ? 'starting' : (residual ? 'recovery' : 'stopped')),
    engine: 'WireSock Secure Connect',
    installed: fs.existsSync(WIRESOCK_CLI),
    appCount: launchedProcesses.length,
    message: residual ? 'Serviços WireSock ativos após encerramento anterior. Inicie novamente para reparar ou encerre o modo seletivo.' : undefined
  };
}

function setStatusListener(listener) {
  onStatusChange = typeof listener === 'function' ? listener : () => {};
}

// ── Acessores de estado interno para uso exclusivo em testes ─────────────

function _getTestState() {
  return {
    selectiveActive,
    launchedProcessesCount: launchedProcesses.length,
    pendingCleanupReason,
    stopInProgress: stopPromise !== null
  };
}

function _setTestState({ selectiveActive: sa, launchedProcesses: lp, pendingCleanupReason: pcr, _resetStop } = {}) {
  if (sa !== undefined) selectiveActive = sa;
  if (lp !== undefined) launchedProcesses = lp;
  if (pcr !== undefined) pendingCleanupReason = pcr;
  if (_resetStop) stopPromise = null; // isolamento entre testes que usam stop()
}

module.exports = {
  SERVER_IP,
  prepare: buildWireSockConfig,
  setStatusListener,
  start,
  status,
  stop,
  _stop: stop,              // alias para testes com dependências injetadas
  _cleanupSelectiveSession: cleanupSelectiveSession,
  _spawnAndConfirm: spawnAndConfirm,
  _requestStop: requestStop,
  _processPendingCleanup,
  _getTestState,
  _setTestState
};
