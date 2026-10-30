/**
 * catalog-shared.js — funções puras compartilhadas entre processo principal e renderer.
 *
 * Módulo UMD:
 *  - No Node/CommonJS (catalog-utils, testes):  module.exports = factory()
 *  - No browser sandboxed (via <script>):        globalThis.GhostRouteCatalog = Object.freeze(factory())
 *
 * RESTRIÇÕES obrigatórias:
 *  - SEM require(), import, fs, path, child_process, electron ou qualquer módulo Node
 *  - SEM acesso a DOM ou APIs de browser exclusivas
 *  - Apenas lógica pura e síncrona (exceto removeFromSelectionWithRollback que é async)
 */
(function (root, factory) {
  'use strict';
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.GhostRouteCatalog = Object.freeze(factory());
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // ── Identidade canônica ─────────────────────────────────────────────────

  /**
   * Valida se um ID é seguro para persistir.
   * Rejeita strings vazias (após trim), CR/LF/NUL e IDs muito longos.
   */
  function isValidId(id) {
    if (typeof id !== 'string' || !id.trim()) return false;
    if (/[\r\n\0]/.test(id)) return false;
    if (id.length > 2048) return false;
    return true;
  }

  /**
   * Deriva o ID canônico normalizado de um item de app.
   *
   * Política de casing:
   *  - item.id       : trim (já vem normalizado da descoberta)
   *  - appUserModelId: lowercase + trim
   *  - path          : lowercase + trim
   *
   * ATENÇÃO: o campo launchTarget (AUMID original com casing preservado) NÃO é alterado.
   * Este ID é usado somente para indexação e comparação.
   *
   * Nunca retorna string vazia, com espaços externos ou com caracteres de controle.
   */
  function canonicalId(item) {
    if (!item) return null;
    var id = null;
    if (item.id)              id = String(item.id).trim();
    else if (item.appUserModelId) id = item.appUserModelId.toLowerCase().trim();
    else if (item.path)       id = item.path.toLowerCase().trim();
    return isValidId(id) ? id : null;
  }

  // ── Filtros de UI ──────────────────────────────────────────────────────

  /**
   * Verifica se um item corresponde ao filtro e à query de busca.
   */
  function appMatchesFilter(item, filter, query) {
    var q = (query || '').trim().toLocaleLowerCase('pt-BR');
    if (q && !String(item.name || '').toLocaleLowerCase('pt-BR').includes(q)) return false;
    switch (filter) {
      case 'desktop':      return item.kind !== 'uwp' && item.source !== 'manual';
      case 'store':        return item.kind === 'uwp';
      case 'manual':       return item.source === 'manual';
      case 'compatible':   return item.compatibility === 'supported' || item.compatibility === 'experimental';
      case 'incompatible': return item.compatibility === 'unsupported' || Boolean(item.unavailable);
      default:             return true;
    }
  }

  // ── Transação de seleção ────────────────────────────────────────────────

  /**
   * Remove um ID de um Set de IDs selecionados e persiste.
   * Implementa rollback automático: em falha, o Set original é restaurado.
   *
   * NÃO muta currentIds — cria cópias internas.
   *
   * @param {Set<string>}                             currentIds
   * @param {string}                                  idToRemove
   * @param {(ids: string[]) => Promise<void>}        saveFn
   * @returns {Promise<{ ids: Set<string>, committed: boolean, error?: Error }>}
   */
  function removeFromSelectionWithRollback(currentIds, idToRemove, saveFn) {
    var prev = new Set(currentIds);
    var next = new Set(currentIds);
    next.delete(idToRemove);
    return Promise.resolve(saveFn(Array.from(next))).then(function () {
      return { ids: next, committed: true };
    }, function (err) {
      return { ids: prev, committed: false, error: err };
    });
  }

  return {
    isValidId: isValidId,
    canonicalId: canonicalId,
    appMatchesFilter: appMatchesFilter,
    removeFromSelectionWithRollback: removeFromSelectionWithRollback,
  };
}));
