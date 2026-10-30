'use strict';

/**
 * Guard para prevenir execuções concorrentes de operações assíncronas.
 *
 * Módulo 100% puro:
 *  - sem I/O de arquivo;
 *  - sem processos externos;
 *  - sem dependências de plataforma.
 *
 * Propriedade de token:
 *  Cada acquire() cria um Symbol único e retorna uma função release que só
 *  desbloqueia o guard se o token ainda for o proprietário atual. Uma release
 *  "antiga" (de uma aquisição anterior já liberada) é silenciosamente ignorada
 *  e nunca desbloqueia uma aquisição posterior.
 *
 * Uso:
 *   const guard = createOperationGuard();
 *   const release = guard.acquire('mensagem se já bloqueado');
 *   // ... operação assíncrona ...
 *   release();   // idempotente para esta aquisição específica
 */
function createOperationGuard() {
  // null quando desbloqueado; Symbol do proprietário atual quando bloqueado.
  let _owner = null;

  /**
   * Tenta adquirir o guard.
   * @param {string} [busyMessage] Mensagem do erro se já estiver bloqueado.
   * @returns {Function} Função de liberação exclusiva desta aquisição.
   * @throws {Error} Se o guard já estiver adquirido.
   */
  function acquire(busyMessage) {
    if (_owner !== null) {
      throw new Error(busyMessage || 'Uma operação já está em andamento.');
    }
    const token = Symbol();
    _owner = token;

    // A closure captura o token desta aquisição.
    // Chamadas "stale" (token diferente do atual) são ignoradas silenciosamente.
    return function release() {
      if (_owner === token) {
        _owner = null;
      }
    };
  }

  /** Retorna true se o guard estiver adquirido no momento. */
  function isLocked() {
    return _owner !== null;
  }

  return { acquire, isLocked };
}

module.exports = { createOperationGuard };
