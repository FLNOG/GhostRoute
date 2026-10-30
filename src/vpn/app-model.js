'use strict';

/**
 * Modelo canônico de aplicativo do GhostRoute.
 *
 * SEPARAÇÃO OBRIGATÓRIA:
 *  routeRule    → what goes into AllowedApps (never AUMID, never args, never shared process)
 *  launchTarget → how to open (exe path for desktop, AUMID for UWP)
 *  launchArgs   → launch-only args (never in AllowedApps)
 *
 * Módulo 100% puro: sem I/O, sem processos, sem Electron.
 */

const path = require('node:path');

// ── Processos compartilhados — NUNCA em AllowedApps ───────────────────────
const SHARED_PROCESS_NAMES = new Set([
  'applicationframehost', 'runtimebroker', 'wwahost', 'shellexperiencehost',
  'startmenuexperiencehost', 'searchhost', 'msedgewebview2', 'explorer',
  'svchost', 'csrss', 'winlogon', 'lsass', 'services', 'smss', 'sihost',
  'taskhostw', 'conhost', 'dllhost', 'ctfmon', 'fontdrvhost', 'winit',
  'dwm', 'audiodg', 'spoolsv', 'msdtc', 'wuauclt', 'trustedinstaller',
]);

// ── Interpretadores de shell — atalhos apontando para estes são rejeitados ─
const SHELL_INTERPRETER_NAMES = new Set([
  'cmd', 'powershell', 'pwsh', 'wscript', 'cscript', 'mshta', 'rundll32',
  'regsvr32', 'msiexec', 'bash', 'sh', 'wmic', 'forfiles', 'pcalua',
]);

// ── Padrão AUMID: PackageFamilyName!ApplicationId ─────────────────────────
const AUMID_RE = /^[A-Za-z0-9._-]+_[A-Za-z0-9]+![A-Za-z0-9._-]+$/;

// ── Risco ─────────────────────────────────────────────────────────────────
const ANTICHEAT_PATTERNS = [
  /faceit/i, /easyanticheat|easy anti.?cheat/i, /battleye|battlEye/i,
  /vgc(?:\.exe)?$|vgtray|vanguard/i, /ricochet/i, /xigncode/i,
  /punkbuster|pbsvc|pbsetup/i, /nprotect|gameguard/i,
];

const GAME_RISK_PATTERNS = [
  /\bsteam\b|\bepic games\b|\bepicgameslauncher\b|\briot client\b|\bbattle\.net\b/i,
  /\bubisoft\b|\buplay\b|\bea app\b|\beadesktop\b|\borigin\b|\brockstar\b|\bgog galaxy\b/i,
  /counter.?strike|valorant|fortnite|league of legends|rainbow six|apex legends|\bpubg\b/i,
];

// ── Launchers ─────────────────────────────────────────────────────────────
const LAUNCHER_PATTERNS = [
  { pattern: /\bsteam\b/i, note: 'Steam pode abrir outro executável que não será incluído automaticamente no túnel.' },
  { pattern: /\bepic\s*games\b|\bepicgames\b|\bepic.*launcher\b/i, note: 'Epic Games Launcher pode abrir outro executável que não será incluído automaticamente no túnel.' },
  { pattern: /\briot\s*client\b|\briotclient\b/i, note: 'Riot Client pode abrir outro executável que não será incluído automaticamente no túnel.' },
  { pattern: /\bbattle\.?net\b|\bblizzard.*launcher\b/i, note: 'Battle.net pode abrir outro executável que não será incluído automaticamente no túnel.' },
  { pattern: /\bubisoft\s*connect\b|\buplay\b/i, note: 'Ubisoft Connect pode abrir outro executável que não será incluído automaticamente no túnel.' },
  { pattern: /\bea\s*app\b|\beadesktop\b|\borigin\b/i, note: 'EA App pode abrir outro executável que não será incluído automaticamente no túnel.' },
  { pattern: /\brockstar.*launcher\b/i, note: 'Rockstar Launcher pode abrir outro executável que não será incluído automaticamente no túnel.' },
  { pattern: /\bgog\s*galaxy\b/i, note: 'GOG Galaxy pode abrir outro executável que não será incluído automaticamente no túnel.' },
  { pattern: /\blauncher\b|\bbootstrap(?:per)?\b/i, note: 'Este launcher pode abrir outro executável que não será incluído automaticamente no túnel.' },
];

// ── Funções puras ──────────────────────────────────────────────────────────

function isAumid(value) {
  return AUMID_RE.test(String(value ?? ''));
}

function isSharedProcess(name) {
  if (!name) return false;
  const base = path.basename(String(name), path.extname(String(name))).toLowerCase();
  return SHARED_PROCESS_NAMES.has(base);
}

/**
 * Classifica o risco de um app pelo nome e caminho.
 * Puro: sem I/O.
 */
function classifyRisk(name, execPath) {
  const combined = `${String(name ?? '')} ${String(execPath ?? '')}`;
  if (ANTICHEAT_PATTERNS.some(p => p.test(combined))) {
    return { level: 'blocked', label: 'Anticheat não compatível' };
  }
  if (GAME_RISK_PATTERNS.some(p => p.test(combined))) {
    return { level: 'warning', label: 'Jogo ou launcher: use com cautela' };
  }
  return { level: 'none', label: '' };
}

/**
 * Valida um candidato para AllowedApps do WireSock.
 * Retorna a regra canônica ou null em caso de falha.
 *
 * Rejeita: AUMID, shell: URI, vírgula, CR/LF, System32/SysWOW64,
 * processos compartilhados do Windows.
 */
function validateRouteRule(candidate) {
  if (!candidate || typeof candidate !== 'string') return null;
  // Verificar ANTES do trim: CR/LF/NUL sempre rejeitam
  if (/[\r\n\0]/.test(candidate)) return null;
  if (candidate.includes(',')) return null;
  const r = candidate.trim();
  if (!r) return null;
  if (isAumid(r)) return null;
  if (/^shell:/i.test(r)) return null;
  if (/\\windows\\(?:system32|syswow64|winsxs|winsideby)/i.test(r)) return null;
  // Nome de processo simples (sem separadores de caminho)
  if (/^[A-Za-z0-9_. -]+\.exe$/i.test(r) && !r.includes('\\') && !r.includes('/')) {
    return isSharedProcess(r) ? null : r;
  }
  // Caminho absoluto
  if (path.isAbsolute(r)) {
    return isSharedProcess(path.basename(r)) ? null : r;
  }
  return null;
}

function detectLauncher(name, execPath) {
  const combined = `${String(name ?? '')} ${path.basename(String(execPath ?? ''))}`;
  for (const { pattern, note } of LAUNCHER_PATTERNS) {
    if (pattern.test(combined)) return { isLauncher: true, launcherNote: note };
  }
  return { isLauncher: false, launcherNote: '' };
}

/**
 * Parse conservador de argumentos Windows.
 *
 * Política conservadora documentada:
 *  - Rejeita CR, LF, NUL (controles)
 *  - Rejeita operadores de shell (&|<>^`$)
 *  - Rejeita aspas não fechadas
 *  - Trata \" como aspas literal dentro de string quotada
 *  - Limita tamanho e quantidade
 *
 * NÃO garante compatibilidade total com CommandLineToArgvW.
 * Use apenas para argumentos de origem confiável (atalhos locais).
 */
function parseWindowsArgs(argString) {
  if (!argString || typeof argString !== 'string') return [];
  // Controles e NUL sempre rejeitam (antes do trim)
  if (/[\r\n\0]/.test(argString)) return null;
  const s = argString.trim();
  if (!s) return [];
  if (s.length > 4096) return null;
  // Operadores de shell e interpolação de variáveis
  if (/[&|<>^`$]/.test(s)) return null;

  const args = [];
  let current = '';
  let inQuote = false;
  let i = 0;

  while (i < s.length) {
    const ch = s[i];
    if (ch === '"') {
      inQuote = !inQuote;
      i++;
    } else if (ch === '\\' && inQuote && i + 1 < s.length && s[i + 1] === '"') {
      // \" dentro de string quotada → aspas literal
      current += '"';
      i += 2;
    } else if (ch === '\\' && inQuote && i + 1 < s.length && s[i + 1] === '\\') {
      // \\ dentro de string quotada → barra literal
      current += '\\';
      i += 2;
    } else if (ch === ' ' && !inQuote) {
      if (current) { args.push(current); current = ''; }
      i++;
    } else {
      current += ch;
      i++;
    }
  }

  if (inQuote) return null; // aspas não fechadas → rejeitar
  if (current) args.push(current);
  if (args.length > 64) return null;
  return args;
}

function migrateOldItem(item) {
  if (!item) return null;
  const executablePath = String(item.path ?? '');
  if (!executablePath) return null;
  const name = String(item.name ?? path.basename(executablePath, '.exe')).trim();
  if (!name) return null;
  const source = item.source === 'manual' ? 'manual' : 'installed';
  const routeRule = validateRouteRule(executablePath);
  if (!routeRule) return null;
  const { isLauncher, launcherNote } = detectLauncher(name, executablePath);
  return {
    id: executablePath.toLowerCase(),
    name,
    kind: 'desktop',
    source,
    path: executablePath,
    routeRule,
    launchTarget: executablePath,
    launchArgs: Array.isArray(item.launchArgs) ? item.launchArgs : [],
    workingDirectory: '',
    packageFamilyName: '',
    appUserModelId: '',
    installRoot: '',
    running: false,
    risk: classifyRisk(name, executablePath),
    compatibility: 'supported',
    isLauncher,
    launcherNote,
  };
}

module.exports = {
  ANTICHEAT_PATTERNS,
  GAME_RISK_PATTERNS,
  LAUNCHER_PATTERNS,
  SHARED_PROCESS_NAMES,
  SHELL_INTERPRETER_NAMES,
  classifyRisk,
  detectLauncher,
  isAumid,
  isSharedProcess,
  migrateOldItem,
  parseWindowsArgs,
  validateRouteRule,
};
