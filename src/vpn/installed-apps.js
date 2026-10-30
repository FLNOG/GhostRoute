'use strict';

const { execFile } = require('node:child_process');
const fs   = require('node:fs');
const path = require('node:path');
const {
  detectLauncher, parseWindowsArgs, validateRouteRule, classifyRisk: classifyRiskModel,
} = require('./app-model');

// ── Script de descoberta de atalhos ───────────────────────────────────────
// Captura TargetPath, Arguments e WorkingDirectory, além de filtrar
// atalhos que apontam para interpretadores de shell.
const DISCOVERY_SCRIPT = `
$OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$shell = New-Object -ComObject WScript.Shell
$shellInterps = @('cmd','powershell','pwsh','wscript','cscript','mshta','rundll32','regsvr32','msiexec','bash','sh','wmic','forfiles')
$roots = @([Environment]::GetFolderPath('Programs'), [Environment]::GetFolderPath('CommonPrograms')) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
$items = foreach ($root in $roots) {
  Get-ChildItem -LiteralPath $root -Filter '*.lnk' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    try {
      $shortcut = $shell.CreateShortcut($_.FullName)
      $target = [Environment]::ExpandEnvironmentVariables($shortcut.TargetPath)
      if (-not $target -or [IO.Path]::GetExtension($target) -ine '.exe') { return }
      if (-not (Test-Path -LiteralPath $target)) { return }
      $base = [IO.Path]::GetFileNameWithoutExtension($target).ToLower()
      if ($shellInterps -contains $base) { return }
      [pscustomobject]@{
        name             = $_.BaseName
        path             = $target
        arguments        = $shortcut.Arguments
        workingDirectory = $shortcut.WorkingDirectory
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

// ── Filtros e classificação ────────────────────────────────────────────────

const EXCLUDED_APP_PATTERNS = [
  /(?:^|\b)uninst(?:all|aller)?(?:\b|\d)/i,
  /(?:^|\b)(?:setup|installer|repair|modify)(?:\b|\d)/i,
  /(?:^|\b)(?:update|updater)(?:\b|\d)/i,
];

const ANTICHEAT_PATTERNS = [
  /faceit/i, /easyanticheat|easy anti.?cheat/i, /battleye|battlEye/i,
  /vgc(?:\.exe)?$|vgtray|vanguard/i, /ricochet/i, /xigncode/i,
  /punkbuster|pbsvc|pbsetup/i, /nprotect|gameguard/i,
];

const GAME_AND_LAUNCHER_PATTERNS = [
  /steam|epic games|epicgameslauncher|riot client|riotclient|battle\.net|battlenet/i,
  /ubisoft|uplay|ea app|eadesktop|origin|rockstar|gog galaxy/i,
  /counter.?strike|valorant|fortnite|league of legends|rainbow six|apex legends|pubg/i,
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
  if (ANTICHEAT_PATTERNS.some(p => p.test(combined))) {
    return { level: 'blocked', label: 'Anticheat não compatível' };
  }
  if (GAME_AND_LAUNCHER_PATTERNS.some(p => p.test(combined))) {
    return { level: 'warning', label: 'Jogo ou launcher: use com cautela' };
  }
  return { level: 'none', label: '' };
}

// ── normalizeItem ─────────────────────────────────────────────────────────

/**
 * Normaliza um item de aplicativo para o formato canônico.
 * Suporta tanto o modelo antigo { name, path } quanto o novo modelo completo.
 * Retorna null para itens inválidos.
 */
function normalizeItem(item) {
  if (!item) return null;

  // Novo modelo UWP: validação mínima e pass-through
  if (item.kind === 'uwp') {
    if (!item.appUserModelId || !item.name) return null;
    return item;
  }

  const executablePath = String(item?.path || '');
  const name = String(item?.name || path.basename(executablePath, '.exe')).trim();
  if (!name || !path.isAbsolute(executablePath) || path.extname(executablePath).toLowerCase() !== '.exe') return null;
  if (!fs.existsSync(executablePath)) return null;

  const source = item?.source === 'manual' ? 'manual' : 'installed';
  const id = executablePath.toLowerCase();

  // Já tem novo modelo (routeRule presente): preservar campos extras
  if (item?.routeRule) {
    return { ...item, id, name, path: executablePath, source };
  }

  // Modelo antigo: retornar formato mínimo compatível
  return { id, name, path: executablePath, source };
}

// ── Processos em execução ─────────────────────────────────────────────────

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

// ── Discord ────────────────────────────────────────────────────────────────

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

// ── Descoberta principal ───────────────────────────────────────────────────

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
  return parsed.map(raw => {
    // Build normalized item with new model fields
    const normalBase = normalizeItem({ ...raw, source: 'installed' });
    if (!normalBase || isExcludedApp(normalBase) || seen.has(normalBase.id)) return null;
    seen.add(normalBase.id);

    const risk = classifyAppRisk(normalBase);
    const { isLauncher, launcherNote } = detectLauncher(normalBase.name, normalBase.path);
    const routeRule = validateRouteRule(normalBase.path);

    // Arguments from shortcut (desktop only)
    const rawArgs = String(raw.arguments || '').trim();
    const rawWd   = String(raw.workingDirectory || '').trim();
    let launchArgs = [];
    let launchArgsAmbiguous = false;
    if (rawArgs) {
      const parsed = parseWindowsArgs(rawArgs);
      if (parsed === null) { launchArgsAmbiguous = true; }
      else { launchArgs = parsed; }
    }

    // workingDirectory: preservar somente se absoluto (validado ao usar)
    const workingDirectory = (rawWd && path.isAbsolute(rawWd)) ? rawWd : '';

    return {
      ...normalBase,
      kind: 'desktop',
      source: 'installed',
      routeRule: routeRule || normalBase.path,
      launchTarget: normalBase.path,
      launchArgs,
      launchArgsAmbiguous: launchArgsAmbiguous || false,
      workingDirectory,
      packageFamilyName: '',
      appUserModelId: '',
      installRoot: '',
      running: false,
      risk,
      compatibility: routeRule ? 'supported' : 'unsupported',
      isLauncher,
      launcherNote,
    };
  }).filter(Boolean).sort((left, right) => left.name.localeCompare(right.name, 'pt-BR'));
}

module.exports = {
  classifyAppRisk,
  discoverInstalledApps,
  findDiscordExecutable,
  isExcludedApp,
  normalizeItem,
  runningExecutablePaths,
};
