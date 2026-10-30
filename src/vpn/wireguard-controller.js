const { execFile, spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const WIREGUARD_DIR = path.join(process.env.ProgramFiles || 'C:\\Program Files', 'WireGuard');
const WIREGUARD_EXE = path.join(WIREGUARD_DIR, 'wireguard.exe');
const WG_EXE = path.join(WIREGUARD_DIR, 'wg.exe');
const SECURE_CONFIG_DIR = path.join(WIREGUARD_DIR, 'Data', 'Configurations');

function command(file, args, options = {}) {
  return new Promise((resolve, reject) => {
    execFile(file, args, { windowsHide: true, timeout: 15000, ...options }, (error, stdout, stderr) => {
      if (error) {
        error.details = String(stderr || stdout || error.message).trim();
        reject(error);
        return;
      }
      resolve({ stdout: String(stdout).trim(), stderr: String(stderr).trim() });
    });
  });
}

function tunnelNameFromConfig(configPath) {
  const filename = path.basename(configPath);
  const name = filename.toLowerCase().endsWith('.conf.dpapi')
    ? filename.slice(0, -'.conf.dpapi'.length)
    : path.basename(filename, path.extname(filename));
  if (!/^[a-zA-Z0-9_=+.-]{1,32}$/.test(name)) {
    throw new Error('O nome do arquivo deve ter até 32 caracteres e usar somente letras, números, ponto, hífen ou sublinhado.');
  }
  return name;
}

function validateConfigPath(configPath) {
  if (typeof configPath !== 'string' || !path.isAbsolute(configPath)) {
    throw new Error('Selecione uma configuração WireGuard local.');
  }
  const encrypted = configPath.toLowerCase().endsWith('.conf.dpapi');
  if (!encrypted && (!configPath.toLowerCase().endsWith('.conf') || !fs.existsSync(configPath))) {
    throw new Error('A configuração WireGuard selecionada não existe ou não é compatível.');
  }
  return { configPath, tunnelName: tunnelNameFromConfig(configPath) };
}

function secureConfigPath(configPath) {
  const tunnelName = tunnelNameFromConfig(configPath);
  return path.join(SECURE_CONFIG_DIR, `${tunnelName}.conf.dpapi`);
}

function escapePowerShellSingleQuoted(value) {
  return String(value).replaceAll("'", "''");
}

function quoteWindowsArgument(value) {
  const text = String(value);
  return `"${text.replaceAll('"', '\\"')}"`;
}

async function runElevatedWireGuard(args) {
  if (!fs.existsSync(WIREGUARD_EXE)) throw new Error('WireGuard oficial não encontrado em Arquivos de Programas.');
  const argumentLine = args.map(quoteWindowsArgument).join(' ');
  const script = [
    `$process = Start-Process -FilePath '${escapePowerShellSingleQuoted(WIREGUARD_EXE)}'`,
    `-ArgumentList '${escapePowerShellSingleQuoted(argumentLine)}' -Verb RunAs -Wait -PassThru;`,
    'exit $process.ExitCode'
  ].join(' ');
  return new Promise((resolve, reject) => {
    const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let stderr = '';
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', code => {
      if (code === 0) resolve();
      else if (code === 1223) reject(new Error('A solicitação de administrador foi cancelada.'));
      else reject(new Error(stderr.trim() || `O WireGuard não aceitou a operação solicitada (código ${code}).`));
    });
  });
}

async function isServiceRunning(tunnelName) {
  try {
    const result = await command('sc.exe', ['query', `WireGuardTunnel$${tunnelName}`]);
    return /:\s*4\s+/i.test(result.stdout);
  } catch {
    return false;
  }
}

async function getWireGuardStats(tunnelName) {
  if (!fs.existsSync(WG_EXE)) return null;
  try {
    const result = await command(WG_EXE, ['show', tunnelName, 'dump']);
    const lines = result.stdout.split(/\r?\n/).filter(Boolean);
    if (lines.length < 2) return null;
    const peer = lines[1].split('\t');
    return {
      latestHandshake: Number(peer[4] || 0),
      receivedBytes: Number(peer[5] || 0),
      sentBytes: Number(peer[6] || 0)
    };
  } catch {
    return null;
  }
}

async function getPublicIp() {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 7000);
  try {
    const response = await fetch('https://api.ipify.org?format=json', {
      signal: controller.signal,
      headers: { Accept: 'application/json' }
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    return typeof data.ip === 'string' ? data.ip : null;
  } finally {
    clearTimeout(timeout);
  }
}

async function status(configPath) {
  if (!configPath) return { state: 'disconnected', installed: fs.existsSync(WIREGUARD_EXE) };
  const { tunnelName } = validateConfigPath(configPath);
  const running = await isServiceRunning(tunnelName);
  if (!running) return { state: 'disconnected', installed: fs.existsSync(WIREGUARD_EXE), tunnelName };
  const stats = await getWireGuardStats(tunnelName);
  const handshakeAge = stats?.latestHandshake
    ? Math.floor(Date.now() / 1000) - stats.latestHandshake
    : null;
  const state = handshakeAge !== null && handshakeAge <= 180 ? 'connected' : 'validating';
  return { state, running: true, installed: true, tunnelName, stats };
}

async function connect(configPath) {
  const validated = validateConfigPath(configPath);
  if (await isServiceRunning(validated.tunnelName)) return status(configPath);
  await runElevatedWireGuard(['/installtunnelservice', validated.configPath]);
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (await isServiceRunning(validated.tunnelName)) {
      const current = await status(configPath);
      try { current.publicIp = await getPublicIp(); } catch { current.publicIp = null; }
      return current;
    }
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  throw new Error('O serviço foi solicitado, mas não entrou em execução dentro do tempo esperado.');
}

async function disconnect(configPath) {
  const { tunnelName } = validateConfigPath(configPath);
  if (!(await isServiceRunning(tunnelName))) return status(configPath);
  await runElevatedWireGuard(['/uninstalltunnelservice', tunnelName]);
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (!(await isServiceRunning(tunnelName))) return status(configPath);
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  throw new Error('O serviço não foi removido dentro do tempo esperado.');
}

module.exports = { WIREGUARD_EXE, connect, disconnect, secureConfigPath, status, validateConfigPath };
