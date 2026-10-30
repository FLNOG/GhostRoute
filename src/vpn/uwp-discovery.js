'use strict';

/**
 * Descoberta de aplicativos Microsoft Store / UWP via PowerShell.
 *
 * Limitações conhecidas:
 *  - O WireSock não suporta AUMID como AllowedApps.
 *  - AUMID é usado somente como launchTarget.
 *  - Apps com processos compartilhados (ApplicationFrameHost, etc.) são marcados
 *    como unsupported — não é possível roteá-los seletivamente.
 *  - Apps experimental: executável identificado mas caminho não acessível;
 *    o nome do processo pode não ser único.
 *  - Apps supported: executável acessível com caminho estável.
 *
 * A função _runPowerShell é injetável para testes sem PowerShell real.
 */

const path = require('node:path');
const { execFile } = require('node:child_process');
const { validateRouteRule, isSharedProcess, isAumid, detectLauncher, classifyRisk } = require('./app-model');

// ── Script de descoberta ───────────────────────────────────────────────────
// Filtra pacotes não-sistema com pelo menos uma Application com Executable.
// Não varre WindowsApps recursivamente; usa apenas dados do manifesto.
const UWP_DISCOVERY_SCRIPT = `
$OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$ErrorActionPreference = 'SilentlyContinue'
$excludePfx = @(
  'Microsoft.UI.', 'Microsoft.VCLibs', 'Microsoft.NET.', 'Microsoft.Desktop.',
  'Microsoft.WindowsDesktop', 'Microsoft.Services.Store', 'Microsoft.Direct',
  'Microsoft.VC.', 'Microsoft.Advertising', 'Microsoft.HEVCVideoExtension',
  'Microsoft.AV1VideoExtension', 'Microsoft.HEIFImageExtension',
  'Microsoft.RawImageExtension', 'Microsoft.VP9VideoExtensions',
  'Microsoft.WebMediaExtensions', 'Microsoft.WebpImageExtension',
  'Microsoft.MicrosoftEdgeDevToolsClient',
  'Windows.', 'MicrosoftWindows.', 'NcsiUwpApp', 'Microsoft.BingNews.8'
)
$packages = Get-AppxPackage | Where-Object {
  $n = $_.Name
  $ok = $true
  foreach ($p in $excludePfx) { if ($n.StartsWith($p)) { $ok = $false; break } }
  $ok -and $_.InstallLocation -and $_.PackageFamilyName
} | Sort-Object Name
$result = foreach ($pkg in $packages) {
  try {
    $mf = Get-AppxPackageManifest $pkg.PackageFullName
    if (-not $mf.Package.Applications.Application) { continue }
    foreach ($app in @($mf.Package.Applications.Application)) {
      if (-not $app.Executable) { continue }
      $aumid = "$($pkg.PackageFamilyName)!$($app.Id)"
      $exeRel  = $app.Executable
      $exeBase = [IO.Path]::GetFileName($exeRel)
      $root    = $pkg.InstallLocation
      $full    = [IO.Path]::Combine($root, $exeRel)
      $access  = Test-Path -LiteralPath $full -ErrorAction SilentlyContinue
      $dn = ''
      try { $dn = $app.VisualElements.DisplayName } catch {}
      if (-not $dn -or $dn -match '^ms-resource:') { $dn = $pkg.Name }
      [pscustomobject]@{
        name              = $dn
        packageName       = $pkg.Name
        packageFamilyName = $pkg.PackageFamilyName
        appUserModelId    = $aumid
        executable        = $exeRel
        executableBasename = $exeBase
        installRoot       = $root
        fullExePath       = if ($access) { $full } else { '' }
        accessible        = $access
      }
    }
  } catch {}
}
if ($result) { $result | ConvertTo-Json -Compress -Depth 2 } else { '[]' }
`;

// ── Normalização pura (sem I/O) ────────────────────────────────────────────

/**
 * Normaliza um item bruto retornado pelo script PowerShell para o modelo canônico.
 * Função pura e injetável em testes.
 *
 * Compatibilidade determinada por:
 *  supported    — executável acessível e não compartilhado
 *  experimental — apenas basename disponível e não compartilhado
 *  unsupported  — processo compartilhado, sem executável, ou routeRule inválida
 */
function normalizeUwpItem(raw) {
  if (!raw || !raw.packageFamilyName || !raw.appUserModelId) return null;

  const name = String(raw.name || raw.packageName || '').trim();
  if (!name) return null;

  if (!isAumid(raw.appUserModelId)) return null;

  const execBasename = String(raw.executableBasename || '').trim();
  const fullExePath  = String(raw.fullExePath || '').trim();

  let routeRule = '';
  let compatibility = 'unsupported';

  if (!execBasename) {
    compatibility = 'unsupported';
  } else if (isSharedProcess(execBasename)) {
    compatibility = 'unsupported';
  } else if (fullExePath) {
    const rule = validateRouteRule(fullExePath);
    if (rule) { routeRule = rule; compatibility = 'supported'; }
    else { compatibility = 'unsupported'; }
  } else {
    const rule = validateRouteRule(execBasename);
    if (rule) { routeRule = rule; compatibility = 'experimental'; }
    else { compatibility = 'unsupported'; }
  }

  const { isLauncher, launcherNote } = detectLauncher(name, execBasename);
  const risk = classifyRisk(name, execBasename);

  return {
    id: raw.appUserModelId.toLowerCase(),
    name,
    kind: 'uwp',
    source: 'store',
    path: fullExePath,
    routeRule,
    launchTarget: raw.appUserModelId,
    launchArgs: [],
    packageFamilyName: raw.packageFamilyName,
    appUserModelId: raw.appUserModelId,
    installRoot: String(raw.installRoot || ''),
    running: false,
    risk,
    compatibility,
    isLauncher,
    launcherNote,
  };
}

// ── Runner PowerShell (real) ───────────────────────────────────────────────

function defaultRunPowerShell(script) {
  return new Promise((resolve, reject) => {
    const encoded = Buffer.from(script, 'utf16le').toString('base64');
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
      { windowsHide: true, timeout: 30000, maxBuffer: 8 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error) return reject(new Error(String(stderr || error.message).trim()));
        resolve(String(stdout).trim());
      });
  });
}

// ── Descoberta ────────────────────────────────────────────────────────────

/**
 * Descobre aplicativos Microsoft Store/UWP.
 * @param {Function|null} _runPowerShell Injetável para testes.
 */
async function discoverUwpApps(_runPowerShell = null) {
  const runPS = _runPowerShell || defaultRunPowerShell;
  let rawItems = [];
  try {
    const output = await runPS(UWP_DISCOVERY_SCRIPT);
    rawItems = output ? JSON.parse(output) : [];
    if (!Array.isArray(rawItems)) rawItems = [rawItems];
  } catch {
    return [];
  }

  const seen = new Set();
  return rawItems
    .map(normalizeUwpItem)
    .filter(item => {
      if (!item) return false;
      if (seen.has(item.id)) return false;
      seen.add(item.id);
      return true;
    })
    .sort((a, b) => a.name.localeCompare(b.name, 'pt-BR'));
}

module.exports = { UWP_DISCOVERY_SCRIPT, discoverUwpApps, normalizeUwpItem };
