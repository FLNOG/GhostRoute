const { execFile, spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const WG_EXE = path.join(process.env.ProgramFiles || 'C:\\Program Files', 'WireGuard', 'wg.exe');
const SERVER_PUBLIC_KEY = 'KCZBfJDh4NlhY1O9yyBO9QqaTDN9zOq6Skky3wXMDVg=';
const SERVER_ENDPOINT = '193.122.219.14:51820';

function command(file, args, input = '') {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', code => {
      if (code === 0) resolve(stdout.trim());
      else reject(new Error(stderr.trim() || `A operação criptográfica falhou (código ${code}).`));
    });
    child.stdin.end(input);
  });
}

function encodePowerShell(script) {
  return Buffer.from(script, 'utf16le').toString('base64');
}

async function protectWithDpapi(secret) {
  const script = [
    "$ErrorActionPreference = 'Stop'",
    'Add-Type -AssemblyName System.Security',
    '$value = [Console]::In.ReadToEnd()',
    '$bytes = [Text.Encoding]::UTF8.GetBytes($value)',
    '$protected = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)',
    '[Console]::Out.Write([Convert]::ToBase64String($protected))'
  ].join('; ');
  return command('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encodePowerShell(script)], secret);
}

async function unprotectWithDpapi(protectedValue) {
  const script = [
    "$ErrorActionPreference = 'Stop'",
    'Add-Type -AssemblyName System.Security',
    '$value = [Console]::In.ReadToEnd()',
    '$bytes = [Convert]::FromBase64String($value)',
    '$plain = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)',
    '[Console]::Out.Write([Text.Encoding]::UTF8.GetString($plain))'
  ].join('; ');
  return command('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encodePowerShell(script)], protectedValue);
}

function identityPath(userDataPath) {
  return path.join(userDataPath, 'device-identity.json');
}

function publicIdentity(identity) {
  if (!identity) return { exists: false };
  return {
    exists: true,
    deviceId: identity.deviceId,
    deviceName: identity.deviceName,
    publicKey: identity.publicKey,
    address: identity.address || '',
    createdAt: identity.createdAt,
    status: identity.status || 'pending'
  };
}

function load(userDataPath) {
  try {
    const identity = JSON.parse(fs.readFileSync(identityPath(userDataPath), 'utf8'));
    if (!identity.publicKey || !identity.privateKeyDpapi) return null;
    return identity;
  } catch {
    return null;
  }
}

async function generate(userDataPath) {
  const existing = load(userDataPath);
  if (existing) return publicIdentity(existing);
  if (!fs.existsSync(WG_EXE)) throw new Error('O utilitário oficial wg.exe não foi encontrado.');

  const privateKey = await command(WG_EXE, ['genkey']);
  const publicKey = await command(WG_EXE, ['pubkey'], `${privateKey}\n`);
  const privateKeyDpapi = await protectWithDpapi(privateKey);
  const identity = {
    version: 1,
    deviceId: crypto.randomUUID(),
    deviceName: os.hostname(),
    publicKey,
    privateKeyDpapi,
    createdAt: new Date().toISOString(),
    status: 'pending'
  };
  fs.mkdirSync(userDataPath, { recursive: true });
  fs.writeFileSync(identityPath(userDataPath), JSON.stringify(identity, null, 2), { mode: 0o600 });
  return publicIdentity(identity);
}

function requestText(identity) {
  const item = publicIdentity(identity);
  if (!item.exists) throw new Error('Gere a identidade deste computador primeiro.');
  return [
    'GhostRoute - solicitação de dispositivo',
    `Dispositivo: ${item.deviceName}`,
    `ID: ${item.deviceId}`,
    `Chave pública: ${item.publicKey}`
  ].join('\n');
}

function activate(userDataPath, address) {
  const normalizedAddress = String(address || '').trim();
  const match = normalizedAddress.match(/^10\.77\.0\.(\d{1,3})\/32$/);
  const host = Number(match?.[1]);
  if (!match || host < 2 || host > 254) throw new Error('Informe um endereço GhostRoute válido, como 10.77.0.3/32.');
  const identity = load(userDataPath);
  if (!identity) throw new Error('Gere a identidade deste computador primeiro.');
  identity.address = normalizedAddress;
  identity.status = 'active';
  identity.activatedAt = new Date().toISOString();
  fs.writeFileSync(identityPath(userDataPath), JSON.stringify(identity, null, 2), { mode: 0o600 });
  return publicIdentity(identity);
}

async function materializeConfig(userDataPath) {
  const identity = load(userDataPath);
  if (!identity || identity.status !== 'active' || !identity.address) {
    throw new Error('A identidade deste computador ainda não foi ativada.');
  }
  const privateKey = await unprotectWithDpapi(identity.privateKeyDpapi);
  const configPath = path.join(userDataPath, `ghostroute-session-${crypto.randomUUID()}.conf`);
  const content = [
    '[Interface]',
    `PrivateKey = ${privateKey}`,
    `Address = ${identity.address}`,
    '',
    '[Peer]',
    `PublicKey = ${SERVER_PUBLIC_KEY}`,
    `Endpoint = ${SERVER_ENDPOINT}`,
    'AllowedIPs = 0.0.0.0/0',
    'PersistentKeepalive = 25',
    ''
  ].join('\r\n');
  fs.writeFileSync(configPath, content, { mode: 0o600 });
  return configPath;
}

function removeMaterializedConfig(configPath) {
  if (typeof configPath === 'string' && path.basename(configPath).startsWith('ghostroute-session-')) {
    try { fs.rmSync(configPath, { force: true }); } catch {}
  }
}

function cleanupStaleConfigs(userDataPath) {
  if (!fs.existsSync(userDataPath)) return 0;
  let removed = 0;
  for (const name of fs.readdirSync(userDataPath)) {
    if (!/^ghostroute-session-[0-9a-f-]+\.conf$/i.test(name) && name !== 'wiresock.generated.conf') continue;
    try {
      fs.rmSync(path.join(userDataPath, name), { force: true });
      removed += 1;
    } catch {}
  }
  return removed;
}

module.exports = { activate, cleanupStaleConfigs, generate, load, materializeConfig, publicIdentity, removeMaterializedConfig, requestText };
