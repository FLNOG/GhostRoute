'use strict';

/**
 * Lógica pura para determinar o estado dos itens do menu da bandeja
 * com base no estado do modo seletivo.
 * Módulo sem dependências de Electron — testável de forma isolada.
 */

const STATE_LABELS = {
  running:  'Ativo',
  starting: 'Iniciando\u2026',
  stopped:  'Parado',
  recovery: 'Recupera\u00e7\u00e3o',
  error:    'Erro'
};

/**
 * Retorna os dados necessários para montar o menu da bandeja
 * a partir do estado atual do modo seletivo.
 *
 * @param {string} selState - Estado atual do selective-controller
 * @returns {{ statusLabel: string, disconnectEnabled: boolean }}
 */
function selectiveStateForMenu(selState) {
  return {
    statusLabel:       `Estado: ${STATE_LABELS[selState] || selState}`,
    disconnectEnabled: selState === 'running' || selState === 'recovery'
  };
}

module.exports = { selectiveStateForMenu, STATE_LABELS };
