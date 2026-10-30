const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('ghostRoute', {
  loadConfig: () => ipcRenderer.invoke('config:load'),
  selectConfig: () => ipcRenderer.invoke('vpn:select-config'),
  status: configPath => ipcRenderer.invoke('vpn:status', configPath),
  connect: configPath => ipcRenderer.invoke('vpn:connect', configPath),
  disconnect: configPath => ipcRenderer.invoke('vpn:disconnect', configPath),
  diagnostics: () => ipcRenderer.invoke('vpn:diagnostics'),
  listApps: () => ipcRenderer.invoke('apps:list'),
  addManualApp: () => ipcRenderer.invoke('apps:add-manual'),
  saveSelectedApps: apps => ipcRenderer.invoke('apps:save-selection', apps),
  identityStatus: () => ipcRenderer.invoke('identity:status'),
  generateIdentity: () => ipcRenderer.invoke('identity:generate'),
  activateIdentity: address => ipcRenderer.invoke('identity:activate', address),
  copyIdentityRequest: () => ipcRenderer.invoke('identity:copy-request'),
  selectiveStatus: () => ipcRenderer.invoke('selective:status'),
  startSelective: options => ipcRenderer.invoke('selective:start', options),
  stopSelective: () => ipcRenderer.invoke('selective:stop'),
  onSelectiveStatus: callback => ipcRenderer.on('selective:status-changed', (_event, status) => callback(status)),
  requestQuit: () => ipcRenderer.invoke('app:request-quit'),
  onShutdownFailed: callback => ipcRenderer.on('app:shutdown-failed', (_event, msg) => callback(msg))
});
