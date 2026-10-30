'use strict';

/**
 * Lógica pura de catálogo — Única implementação usada por produção e testes.
 * main.js importa e usa diretamente estas funções.
 *
 * As funções puras isValidId, canonicalId e appMatchesFilter vêm de catalog-shared.js,
 * que é também carregado pelo renderer sandboxed via <script>.
 */

const { isValidId, canonicalId, appMatchesFilter } = require('./catalog-shared');
const { migrateOldItem, validateRouteRule } = require('./vpn/app-model');
const installedApps = require('./vpn/installed-apps');

// isValidId, canonicalId e appMatchesFilter importadas de catalog-shared
// (ver import no topo deste arquivo)

// ── Catálogo ──────────────────────────────────────────────────────────────

/** Constrói um catálogo de teste a partir de um array de apps. */
function buildTestCatalog(apps) {
  const cat = new Map();
  for (const a of (apps || [])) {
    if (a.id) cat.set(a.id, a);
    if (a.appUserModelId) cat.set(a.appUserModelId.toLowerCase(), a);
  }
  return cat;
}

/**
 * Muta o catálogo existente no-place: limpa e preenche com novos apps.
 * Não substitui a instância — referências externas ao Map permanecem válidas.
 * main.js chama esta função em updateAppCatalog.
 */
function updateCatalogInPlace(catalog, apps) {
  catalog.clear();
  for (const a of (apps || [])) {
    if (a.id) catalog.set(a.id, a);
    if (a.appUserModelId) catalog.set(a.appUserModelId.toLowerCase(), a);
  }
}

/**
 * Resolve apps usando um catálogo fornecido.
 * Retorna versões canônicas — nunca confia em campos do renderer.
 * Desktop sem catálogo: fallback local via migrateOldItem.
 */
function resolveAppsFromCatalog(rawApps, catalog) {
  return (Array.isArray(rawApps) ? rawApps : []).map(item => {
    if (!item) return null;
    if (item.id && catalog.has(item.id)) return catalog.get(item.id);
    if (item.appUserModelId && catalog.has(item.appUserModelId.toLowerCase())) return catalog.get(item.appUserModelId.toLowerCase());
    if (item.path && catalog.has(item.path.toLowerCase())) return catalog.get(item.path.toLowerCase());
    if ((!item.kind || item.kind === 'desktop') && item.path) {
      const migrated = migrateOldItem(item);
      if (migrated) return migrated;
    }
    return null;
  }).filter(Boolean);
}

/**
 * Resolve IDs contra o catálogo.
 * Se qualquer ID estiver ausente:
 *   1. chama refreshFn() UMA vez
 *   2. tenta novamente
 *   3. se ainda faltar, lança erro com lista dos ausentes
 * NUNCA descarta parte da seleção silenciosamente.
 */
async function resolveSelectionWithRefresh(ids, catalog, refreshFn) {
  if (!Array.isArray(ids) || ids.length === 0) return [];

  const tryResolve = () => ids.map(id => catalog.get(id)).filter(Boolean);

  // Tentativa 1: catálogo atual
  let resolved = tryResolve();
  if (resolved.length === ids.length) return resolved;

  // IDs ausentes → redescoberta
  await refreshFn();

  // Tentativa 2: após refresh
  const missing = ids.filter(id => !catalog.get(id));
  if (missing.length > 0) {
    const preview = missing.slice(0, 3).join(', ');
    const extra = missing.length > 3 ? ` e mais ${missing.length - 3}` : '';
    throw new Error(
      `Aplicativos não encontrados no catálogo: ${preview}${extra}. Atualize a lista de aplicativos.`
    );
  }

  return ids.map(id => catalog.get(id)).filter(Boolean);
}

/**
 * Cria um wrapper de deduplicação para chamadas assíncronas de refresh.
 * Chamadas concorrentes compartilham a mesma Promise em andamento.
 */
function createRefreshDeduplicator(refreshFn) {
  let promise = null;
  return function dedupedRefresh() {
    if (promise) return promise;
    promise = Promise.resolve(refreshFn()).finally(() => { promise = null; });
    return promise;
  };
}

// ── Funções puras de produção — usadas por main.js e testadas diretamente ─

/**
 * Remove um item manual da configuração.
 * Só opera sobre manualApps; nunca remove itens instalados ou UWP.
 * Idempotente: ID ausente em manualApps não é erro.
 * @returns {{ config: object, wasManual: boolean }}
 */
function removeManualFromConfig(config, id) {
  if (!isValidId(id)) throw new Error('ID inválido para remoção.');
  const trimmedId  = String(id).trim();
  const manualApps = config.manualApps    || [];
  const wasManual  = manualApps.some(a => a.id === trimmedId);
  const newManual  = manualApps.filter(a => a.id !== trimmedId);
  const newSelected = (config.selectedAppIds || []).filter(s => s !== trimmedId);
  return {
    config: { ...config, manualApps: newManual, selectedAppIds: newSelected },
    wasManual,
  };
}

/**
 * Valida que todos os itens resolvidos são selecionáveis.
 * Lança erro se qualquer item for unavailable, unsupported ou blocked.
 * Garante "todos ou nenhum" antes de iniciar o modo seletivo.
 */
function validateResolvedSelection(apps) {
  const invalid = (apps || []).filter(a =>
    a.unavailable || a.compatibility === 'unsupported' || a.risk?.level === 'blocked'
  );
  if (invalid.length > 0) {
    const names = invalid.map(a => a.name || a.id).join(', ');
    throw new Error(`Aplicações inválidas na seleção: ${names}. Remova-as antes de iniciar.`);
  }
  return apps;
}

/**
 * Normaliza e valida uma lista de IDs de seleção recebida do renderer.
 *
 * Política de IDs conhecidos:
 *  - Aceita IDs presentes no catálogo (items disponíveis ou indisponíveis catalogados)
 *  - Aceita também IDs de manualApps salvos (para exibir e permitir remoção)
 *  - Rejeita IDs arbitrários não conhecidos (previne injeção do renderer)
 *  - Trim; deduplicação preservando primeira ocorrência; sem CR/LF/NUL
 *
 * @param {any[]} rawIds - IDs brutos do renderer
 * @param {Map} catalog - catálogo atual
 * @param {string[]} [knownManualIds] - IDs de itens manuais já salvos na config
 * @returns {string[]}
 */
function normalizeSelectedIds(rawIds, catalog, knownManualIds) {
  if (!Array.isArray(rawIds)) return [];
  const known = new Set(Array.isArray(knownManualIds)
    ? knownManualIds.filter(id => isValidId(id))
    : []);
  const seen = new Set();
  return rawIds
    .filter(id => {
      if (!isValidId(id)) return false;
      const trimmed = String(id).trim();
      if (!trimmed) return false;
      return catalog.has(trimmed) || known.has(trimmed);
    })
    .map(id => String(id).trim())
    .filter(id => {
      if (seen.has(id)) return false;
      seen.add(id);
      return true;
    });
}

// ── Persistência mínima ───────────────────────────────────────────────────

/**
 * Serializa um item para persistência mínima.
 * NUNCA salva: routeRule, launchTarget, launchArgs, compatibility, risk, installRoot.
 */
function serializeForSave(item) {
  if (!item) return null;
  if (item.kind === 'uwp') {
    if (!item.appUserModelId || !item.name || item.compatibility === 'unsupported') return null;
    return { id: item.id, appUserModelId: item.appUserModelId, name: item.name, kind: 'uwp', source: 'store' };
  }
  const normalized = installedApps.normalizeItem(item);
  if (!normalized) return null;
  return { id: normalized.id, name: normalized.name, path: normalized.path, source: normalized.source || 'installed' };
}

/**
 * Migra config antigo ({ selectedApps: [...] }) para novo formato ({ selectedAppIds, manualApps }).
 * Idempotente: formato novo passa sem alteração.
 */
function migrateOldConfig(oldConfig) {
  const empty = { selectedAppIds: [], manualApps: [] };
  if (!oldConfig) return empty;

  if (Array.isArray(oldConfig.selectedAppIds)) {
    return {
      selectedAppIds: oldConfig.selectedAppIds,
      manualApps: Array.isArray(oldConfig.manualApps) ? oldConfig.manualApps : [],
    };
  }

  const selectedAppIds = [];
  const manualApps = [];

  if (Array.isArray(oldConfig.selectedApps)) {
    for (const item of oldConfig.selectedApps) {
      if (!item) continue;
      if (item.kind === 'uwp' && item.appUserModelId) {
        const id = item.id || item.appUserModelId.toLowerCase();
        if (id && !selectedAppIds.includes(id)) selectedAppIds.push(id);
      } else if (item.path) {
        const id = item.id || item.path.toLowerCase();
        if (id && !selectedAppIds.includes(id)) selectedAppIds.push(id);
        if (item.source === 'manual') {
          if (!manualApps.find(a => a.id === id)) {
            manualApps.push({ id, name: item.name || '', path: item.path });
          }
        }
      }
    }
  }

  return { selectedAppIds, manualApps };
}

// ── Filtros de UI (reimportada de catalog-shared) ────────────────────────
// appMatchesFilter já importada de catalog-shared no topo deste arquivo.

module.exports = {
  appMatchesFilter,
  buildTestCatalog,
  canonicalId,
  createRefreshDeduplicator,
  isValidId,
  migrateOldConfig,
  normalizeSelectedIds,
  removeManualFromConfig,
  resolveAppsFromCatalog,
  resolveSelectionWithRefresh,
  serializeForSave,
  updateCatalogInPlace,
  validateResolvedSelection,
};
