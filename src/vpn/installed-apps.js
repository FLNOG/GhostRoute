const { execFile } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const DISCOVERY_SCRIPT = `
$OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$shell = New-Object -ComObject WScript.Shell
$roots = @([Environment]::GetFolderPath('Programs'), [Environment]::GetFolderPath('CommonPrograms')) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
$items = foreach ($root in $roots) {
  Get-ChildItem -LiteralPath $root -Filter '*.lnk' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    try {
      $shortcut = $shell.CreateShortcut($_.FullName)
      $target = [Environment]::ExpandEnvironmentVariables($shortcut.TargetPath)
      if ($target -and [IO.Path]::GetExtension($target) -ieq '.exe' -and (Test-Path -LiteralPath $target)) {
        [pscustomobject]@{ name = $_.BaseName; path = $target }
      }
    } catch {}
  }
}
$items | Sort-Object name, path -Unique | ConvertTo-Json -Compress
`;

function runPowerShell(script) {
  return new Promise((resolve, reject) => {
    const encoded = Buffer.from(script, 'utf16le').toString('base64');
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
      { windowsHide: true, timeout: 20000, maxBuffer: 4 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error) return reject(new Error(String(stderr || error.message).trim()));
        resolve(String(stdout).trim());
      });
  });
}

function normalizeItem(item) {
  const executablePath = String(item?.path || '');
  const name = String(item?.name || path.basename(executablePath, '.exe')).trim();
  if (!name || !path.isAbsolute(executablePath) || path.extname(executablePath).toLowerCase() !== '.exe') return null;
  if (!fs.existsSync(executablePath)) return null;
  const source = item?.source === 'manual' ? 'manual' : 'installed';
  return { id: executablePath.toLowerCase(), name, path: executablePath, source };
}

const EXCLUDED_APP_PATTERNS = [
  /(?:^|\b)uninst(?:all|aller)?(?:\b|\d)/i,
  /(?:^|\b)(?:setup|installer|repair|modify)(?:\b|\d)/i,
  /(?:^|\b)(?:update|updater)(?:\b|\d)/i
];

const ANTICHEAT_PATTERNS = [
  /faceit/i, /easyanticheat|easy anti.?cheat/i, /battleye|battlEye/i,
  /vgc(?:\.exe)?$|vgtray|vanguard/i, /ricochet/i, /xigncode/i,
  /punkbuster|pbsvc|pbsetup/i, /nprotect|gameguard/i
];

const GAME_AND_LAUNCHER_PATTERNS = [
  /steam|epic games|epicgameslauncher|riot client|riotclient|battle\.net|battlenet/i,
  /ubisoft|uplay|ea app|eadesktop|origin|rockstar|gog galaxy/i,
  /counter.?strike|valorant|fortnite|league of legends|rainbow six|apex legends|pubg/i
];

function isExcludedApp(item) {
  const name = String(item?.name || '');
  const executablePath = String(item?.path || '');
  const combined = `${name} ${path.basename(executablePath)}`;
  if (/\\windows\\(?:system32|syswow64)\\/i.test(executablePath)) return true;
  return EXCLUDED_APP_PATTERNS.some(pattern => pattern.test(combined));
}

function classifyAppRisk(item) {
  const combined = `${String(item?.name || '')} ${String(item?.path || '')}`;
  if (ANTICHEAT_PATTERNS.some(pattern => pattern.test(combined))) {
    return { level: 'blocked', label: 'Anticheat não compatível' };
  }
  if (GAME_AND_LAUNCHER_PATTERNS.some(pattern => pattern.test(combined))) {
    return { level: 'warning', label: 'Jogo ou launcher: use com cautela' };
  }
  return { level: 'none', label: '' };
}

async function runningExecutablePaths() {
  const script = `
$OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
  Where-Object { $_.ExecutablePath } |
  Select-Object -ExpandProperty ExecutablePath -Unique |
  ConvertTo-Json -Compress
`;
  try {
    const output = await runPowerShell(script);
    let parsed = output ? JSON.parse(output) : [];
    if (!Array.isArray(parsed)) parsed = [parsed];
    return new Set(parsed.map(value => String(value).toLowerCase()));
  } catch {
    return new Set();
  }
}

function findDiscordExecutable() {
  const root = path.join(process.env.LOCALAPPDATA || '', 'Discord');
  if (!fs.existsSync(root)) return '';
  const candidates = fs.readdirSync(root, { withFileTypes: true })
    .filter(entry => entry.isDirectory() && entry.name.toLowerCase().startsWith('app-'))
    .map(entry => path.join(root, entry.name, 'Discord.exe'))
    .filter(candidate => fs.existsSync(candidate))
    .sort((left, right) => right.localeCompare(left, undefined, { numeric: true }));
  const rootExecutable = path.join(root, 'Discord.exe');
  return candidates[0] || (fs.existsSync(rootExecutable) ? rootExecutable : '');
}

async function discoverInstalledApps() {
  let parsed = [];
  try {
    const output = await runPowerShell(DISCOVERY_SCRIPT);
    parsed = output ? JSON.parse(output) : [];
    if (!Array.isArray(parsed)) parsed = [parsed];
  } catch {
    parsed = [];
  }

  const discordPath = findDiscordExecutable();
  if (discordPath) {
    parsed = parsed.filter(item => String(item?.name || '').toLowerCase() !== 'discord');
    parsed.push({ name: 'Discord', path: discordPath, source: 'installed' });
  }

  const seen = new Set();
  return parsed.map(item => normalizeItem({ ...item, source: 'installed' })).filter(item => {
    if (!item || isExcludedApp(item) || seen.has(item.id)) return false;
    seen.add(item.id);
    return true;
  }).sort((left, right) => left.name.localeCompare(right.name, 'pt-BR'));
}

module.exports = {
  classifyAppRisk,
  discoverInstalledApps,
  findDiscordExecutable,
  isExcludedApp,
  normalizeItem,
  runningExecutablePaths
};
