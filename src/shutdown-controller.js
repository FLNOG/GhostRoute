'use strict';

/**
 * Coordenador central e idempotente de encerramento do GhostRoute.
 *
 * ── Máquina de estados ─────────────────────────────────────────────────────
 *
 *   idle      → nenhuma operação iniciada
 *   cleaning  → cleanupFn() em andamento; chamadas concorrentes compartilham Promise
 *   cleaned   → cleanup concluído; retry vai direto para attemptQuit (sem repetir cleanup)
 *   quitting  → _allowWindowClose=true; quitFn() em andamento; chamadas compartilham Promise
 *   done      → quitFn() concluiu; todas as chamadas retornam sucesso imediatamente
 *
 * ── Invariantes ────────────────────────────────────────────────────────────
 *
 *   I1  _allowWindowClose=true é definido ANTES da chamada a quitFn().
 *       app.quit() pode disparar o evento 'close' síncronamente; o handler
 *       já deve ver true para não bloquear o próprio encerramento.
 *
 *   I2  Se quitFn lançar: state→'cleaned', _allowWindowClose=false.
 *       Cleanup NÃO se repete; nova solicitação retenta somente o quit.
 *
 *   I3  Se cleanupFn lançar: state→'idle', _allowWindowClose=false.
 *       Nova solicitação repete cleanup + quit.
 *
 *   I4  destroyTrayFn é chamado DEPOIS de quitFn.
 *       Se quitFn lançar, o Tray é preservado (app permanece visível e com menu).
 *
 *   I5  Cleanup executa no máximo uma vez (garantido pelo ciclo de estados).
 *
 *   I6  Chamadas concorrentes durante cleaning ou quitting compartilham a Promise.
 *
 * ── Todas as dependências são injetadas — 100% testável sem Electron. ──────
 */
function createShutdownController({
  cleanupFn,
  quitFn        = () => {},
  showWindowFn  = () => {},
  showErrorFn   = () => {},
  destroyTrayFn = () => {}
} = {}) {
  let state = 'idle';   // 'idle'|'cleaning'|'cleaned'|'quitting'|'done'
  let promise = null;   // Promise compartilhada durante cleaning ou quitting
  let _allowWindowClose = false;
  let _trayHideNotified = false;

  // ── Fase 2: tentativa de quit (chamada somente após cleanup bem-sucedido) ──

  function attemptQuit(origin) {
    // Compartilha quit em andamento
    if (state === 'quitting' && promise) return promise;

    state = 'quitting';

    promise = (async () => {
      // INVARIANTE I1: definir _allowWindowClose ANTES de chamar quitFn.
      // O evento 'close' da BrowserWindow pode ocorrer dentro de app.quit().
      // O handler verifica isAllowedToClose() antes de event.preventDefault();
      // se ainda fosse false, o GhostRoute bloquearia seu próprio encerramento.
      _allowWindowClose = true;

      try {
        quitFn();
        // quitFn concluiu: finalizar
        state = 'done';
        // INVARIANTE I4: Tray destruído DEPOIS de quitFn.
        // Se quitFn lançar, o Tray é preservado para que o app continue visível.
        try { destroyTrayFn(); } catch {}
        return { success: true };
      } catch (quitError) {
        // INVARIANTE I2: quitFn lançou → revertemos para 'cleaned'.
        // Cleanup NÃO será repetido em nova tentativa.
        // Tray preservado (não foi destruído).
        state = 'cleaned';
        promise = null;
        _allowWindowClose = false;
        if (origin !== 'os') {
          try { showWindowFn(); } catch {}
          try { showErrorFn(quitError.message); } catch {}
        }
        return { success: false, error: quitError };
      }
    })();

    return promise;
  }

  // ── Fase 1 + despacho ──────────────────────────────────────────────────────

  function requestShutdown(origin = 'menu') {
    // Já encerrou com sucesso
    if (state === 'done') return Promise.resolve({ success: true });

    // Quit em andamento — compartilha
    if (state === 'quitting' && promise) return promise;

    // Cleanup concluído — retry somente do quit (não repete cleanup)
    if (state === 'cleaned') return attemptQuit(origin);

    // Cleanup em andamento — compartilha
    if (state === 'cleaning' && promise) return promise;

    // state === 'idle': inicia cleanup
    state = 'cleaning';
    promise = (async () => {
      try {
        await cleanupFn();
      } catch (cleanupError) {
        // INVARIANTE I3: cleanup falhou
        state = 'idle';
        promise = null;
        _allowWindowClose = false;
        if (origin !== 'os') {
          try { showWindowFn(); } catch {}
          try { showErrorFn(cleanupError.message); } catch {}
        }
        return { success: false, error: cleanupError };
      }

      // Cleanup concluído: transição síncrona para tentativa de quit.
      // Nenhuma outra chamada pode se interpor aqui (sem await entre os statements).
      state = 'cleaned';
      promise = null;
      return attemptQuit(origin);
    })();

    return promise;
  }

  /**
   * Registra a primeira ocultação da janela para controlar a notificação de bandeja.
   * @returns {boolean} true somente na primeira chamada por instância.
   */
  function noteFirstHide() {
    const isFirst = !_trayHideNotified;
    _trayHideNotified = true;
    return isFirst;
  }

  /**
   * true se cleanup e quitFn concluíram com sucesso.
   * A janela pode ser destruída pelo Electron.
   */
  function isAllowedToClose() { return _allowWindowClose; }

  /**
   * true durante qualquer fase intermediária (cleaning, cleaned, quitting).
   * Usado para bloquear handlers IPC mutáveis durante shutdown.
   */
  function isShuttingDown() { return state !== 'idle' && state !== 'done'; }

  /** true somente quando quitFn concluiu com sucesso. */
  function isDone() { return state === 'done'; }

  /**
   * Retorna o estado interno atual.
   * @returns {'idle'|'cleaning'|'cleaned'|'quitting'|'done'}
   */
  function _getState() { return state; }

  return { requestShutdown, noteFirstHide, isAllowedToClose, isShuttingDown, isDone, _getState };
}

module.exports = { createShutdownController };
