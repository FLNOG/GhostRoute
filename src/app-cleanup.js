'use strict';

/**
 * Fábrica da função de cleanup central do GhostRoute.
 *
 * Sequência obrigatória:
 *   1. Modo seletivo / WireSock (inclui estado recovery)
 *   2. VPN completa WireGuard (somente se caminho configurado e ativa)
 *   3. Limpeza de configurações temporárias autorizadas (não-fatal)
 *
 * Falhas nas etapas 1 ou 2 propagam o erro (impede quit pelo menu, permite retry).
 * Não remove drivers, não desinstala programas, não mata processos externos.
 *
 * Todas as dependências são injetadas — módulo 100% testável sem Electron/WireGuard.
 *
 * @param {object} deps
 * @param {Function} deps.getSelectiveStatus    () → { state: string }
 * @param {Function} deps.stopSelective         async (reason) → void
 * @param {Function} deps.getFullTunnelPath     () → string   (vazio = sem VPN completa)
 * @param {Function} deps.getFullTunnelStatus   async (path) → { state: string }
 * @param {Function} deps.disconnectFullTunnel  async (path) → void
 * @param {Function} deps.cleanupTempFiles      () → void
 */
function createCleanupFn({
  getSelectiveStatus,
  stopSelective,
  getFullTunnelPath,
  getFullTunnelStatus,
  disconnectFullTunnel,
  cleanupTempFiles = () => {}
}) {
  return async () => {
    // 1. Modo seletivo / WireSock — inclui recovery
    const selStatus = getSelectiveStatus();
    if (selStatus.state !== 'stopped') {
      await stopSelective('GhostRoute encerrado pelo usuário.');
    }

    // 2. VPN completa WireGuard
    // Caminho vazio significa que nenhuma VPN completa está configurada.
    const tunnelPath = getFullTunnelPath();
    if (tunnelPath) {
      const vpnStatus = await getFullTunnelStatus(tunnelPath);
      if (vpnStatus.state !== 'disconnected') {
        await disconnectFullTunnel(tunnelPath);
      }
    }

    // 3. Limpeza de configs temporárias (não-fatal — nunca bloqueia o encerramento)
    try { cleanupTempFiles(); } catch {}
  };
}

module.exports = { createCleanupFn };
