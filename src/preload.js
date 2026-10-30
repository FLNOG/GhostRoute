'use strict';

/**
 * preload.js — roda no contexto sandboxed (sandbox:true, nodeIntegration:false).
 *
 * REGRA: somente require('electron') é permitido aqui.
 * Nenhum require local ('./...') pois o contexto sandboxed não garante
 * acesso ao sistema de ficheiros via require.
 *
 * As funções puras (canonicalId, appMatchesFilter, etc.) são carregadas
 * pelo renderer via <script src="catalog-shared.js"> em index.html e ficam
 * disponíveis como globalThis.GhostRouteCatalog.
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('ghostRoute', {
  loadConfig:          ()       => ipcRenderer.invoke('config:load'),
  selectConfig:        ()       => ipcRenderer.invoke('vpn:select-config'),
  status:              p        => ipcRenderer.invoke('vpn:status', p),
  connect:             p        => ipcRenderer.invoke('vpn:connect', p),
  disconnect:          p        => ipcRenderer.invoke('vpn:disconnect', p),
  diagnostics:         ()       => ipcRenderer.invoke('vpn:diagnostics'),
  listApps:            ()       => ipcRenderer.invoke('apps:list'),
  addManualApp:        ()       => ipcRenderer.invoke('apps:add-manual'),
  removeManualApp:     id       => ipcRenderer.invoke('apps:remove-manual', id),
  saveSelectedApps:    ids      => ipcRenderer.invoke('apps:save-selection', ids),
  identityStatus:      ()       => ipcRenderer.invoke('identity:status'),
  generateIdentity:    ()       => ipcRenderer.invoke('identity:generate'),
  activateIdentity:    address  => ipcRenderer.invoke('identity:activate', address),
  copyIdentityRequest: ()       => ipcRenderer.invoke('identity:copy-request'),
  selectiveStatus:     ()       => ipcRenderer.invoke('selective:status'),
  startSelective:      options  => ipcRenderer.invoke('selective:start', options),
  stopSelective:       ()       => ipcRenderer.invoke('selective:stop'),
  onSelectiveStatus:   callback => ipcRenderer.on('selective:status-changed', (_e, s) => callback(s)),
  requestQuit:         ()       => ipcRenderer.invoke('app:request-quit'),
  onShutdownFailed:    callback => ipcRenderer.on('app:shutdown-failed', (_e, msg) => callback(msg)),
});
