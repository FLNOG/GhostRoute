const configField = document.querySelector('#wireGuardConfig');
const selectButton = document.querySelector('#selectButton');
const connectButton = document.querySelector('#connectButton');
const disconnectButton = document.querySelector('#disconnectButton');
const refreshButton = document.querySelector('#refreshButton');
const message = document.querySelector('#message');
const statusPill = document.querySelector('#statusPill');
const handshake = document.querySelector('#handshake');
const received = document.querySelector('#received');
const sent = document.querySelector('#sent');
const publicIp = document.querySelector('#publicIp');
const diagnosticsButton = document.querySelector('#diagnosticsButton');
const dnsStatus = document.querySelector('#dnsStatus');
const dnsServers = document.querySelector('#dnsServers');
const ipv6Status = document.querySelector('#ipv6Status');
const diagnosticsTime = document.querySelector('#diagnosticsTime');
let operationInProgress = false;
const appSearch = document.querySelector('#appSearch');
const selectedAppList = document.querySelector('#selectedAppList');
const installedAppList = document.querySelector('#installedAppList');
const addManualAppButton = document.querySelector('#addManualAppButton');
const refreshAppsButton = document.querySelector('#refreshAppsButton');
const launchAppsToggle = document.querySelector('#launchAppsToggle');
const selectedCount = document.querySelector('#selectedCount');
const startSelectiveButton = document.querySelector('#startSelectiveButton');
const stopSelectiveButton = document.querySelector('#stopSelectiveButton');
const selectiveMessage = document.querySelector('#selectiveMessage');
const selectivePill = document.querySelector('#selectivePill');
const identityPill = document.querySelector('#identityPill');
const identityDetails = document.querySelector('#identityDetails');
const identityDevice = document.querySelector('#identityDevice');
const identityPublicKey = document.querySelector('#identityPublicKey');
const identityMessage = document.querySelector('#identityMessage');
const generateIdentityButton = document.querySelector('#generateIdentityButton');
const copyIdentityButton = document.querySelector('#copyIdentityButton');
const identityActivation = document.querySelector('#identityActivation');
const identityAddress = document.querySelector('#identityAddress');
const activateIdentityButton = document.querySelector('#activateIdentityButton');
let selectiveBusy = false;
let selectiveState = 'stopped';
let availableApps = [];
let selectedPaths = new Set();
let selectiveConfigReady = false;

function cleanErrorMessage(error) {
  return String(error?.message || error).replace(/^Error invoking remote method '[^']+': Error:\s*/i, '');
}

function showMessage(text, type = '') {
  message.textContent = text;
  message.className = type;
}

function formatBytes(value) {
  if (!Number.isFinite(value)) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  let amount = value;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit += 1; }
  return `${amount.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function formatHandshake(timestamp) {
  if (!timestamp) return 'Nenhum handshake observado';
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - timestamp);
  if (seconds < 60) return `há ${seconds} s`;
  return `há ${Math.floor(seconds / 60)} min`;
}

function setUiState(state) {
  const connected = state === 'connected';
  const active = connected || state === 'validating';
  const busy = state === 'connecting' || state === 'disconnecting';
  statusPill.textContent = {
    disconnected: 'Desconectado', connecting: 'Conectando…', connected: 'Conectado',
    validating: 'Validando…', disconnecting: 'Desconectando…', error: 'Erro'
  }[state] || 'Desconectado';
  statusPill.className = `pill ${state}`;
  connectButton.hidden = active;
  disconnectButton.hidden = !active;
  connectButton.disabled = busy || operationInProgress || !configField.value || selectiveState === 'running';
  disconnectButton.disabled = busy || operationInProgress;
  selectButton.disabled = busy || operationInProgress || active;
  refreshButton.disabled = busy || operationInProgress;
  diagnosticsButton.disabled = busy || operationInProgress;
}

function renderStatus(status) {
  const state = status?.state || 'disconnected';
  setUiState(state);
  const stats = status?.stats;
  handshake.textContent = formatHandshake(stats?.latestHandshake);
  received.textContent = formatBytes(stats?.receivedBytes);
  sent.textContent = formatBytes(stats?.sentBytes);
  if (status?.publicIp) publicIp.textContent = status.publicIp;
  if (!status?.installed) showMessage('O WireGuard oficial não foi encontrado.', 'error');
}

function setSelectiveState(state, text) {
  selectiveState = state;
  const running = state === 'running';
  const residual = state === 'recovery';
  selectivePill.textContent = { stopped: 'Parado', starting: 'Iniciando…', running: 'Ativo', recovery: 'Recuperação', error: 'Erro' }[state] || state;
  selectivePill.className = `mini-pill ${state}`;
  startSelectiveButton.hidden = running;
  stopSelectiveButton.hidden = !running && !residual;
  const blocked = selectiveBusy || running;
  startSelectiveButton.disabled = selectiveBusy || !selectiveConfigReady || selectedPaths.size === 0;
  appSearch.disabled = blocked;
  addManualAppButton.disabled = blocked;
  document.querySelectorAll('#selectedAppList input, #installedAppList input').forEach(input => { input.disabled = blocked; });
  refreshAppsButton.disabled = blocked;
  launchAppsToggle.disabled = blocked;
  if (text) selectiveMessage.textContent = text;
  connectButton.disabled = running || residual || operationInProgress || !configField.value;
}

function selectedApps() {
  return availableApps.filter(item => selectedPaths.has(item.path.toLowerCase()));
}

function updateSelectedCount() {
  const count = selectedPaths.size;
  selectedCount.textContent = count === 0 ? 'Nenhum selecionado' : `${count} selecionado${count === 1 ? '' : 's'}`;
  setSelectiveState(selectiveState);
}

function createAppItem(item, selected) {
  const risk = item.risk || { level: 'none', label: '' };
  const blocked = risk.level === 'blocked';
  const label = document.createElement('label');
  label.className = `app-item${blocked ? ' blocked' : ''}`;
  const checkbox = document.createElement('input');
  checkbox.type = 'checkbox';
  checkbox.checked = selected;
  checkbox.disabled = blocked || selectiveBusy || selectiveState === 'running';
  checkbox.addEventListener('change', async () => {
    const key = item.path.toLowerCase();
    if (checkbox.checked) selectedPaths.add(key); else selectedPaths.delete(key);
    renderAppLists();
    updateSelectedCount();
    await window.ghostRoute.saveSelectedApps(selectedApps());
  });
  const icon = item.icon ? document.createElement('img') : document.createElement('span');
  if (item.icon) { icon.src = item.icon; icon.alt = ''; }
  else { icon.className = 'app-fallback'; icon.textContent = item.name.slice(0, 1).toUpperCase(); }
  const details = document.createElement('span');
  details.className = 'app-details';
  const name = document.createElement('strong');
  name.textContent = item.name;
  const appPath = document.createElement('small');
  appPath.textContent = item.path;
  details.append(name, appPath);
  const meta = document.createElement('span');
  meta.className = 'app-meta';
  if (item.running) {
    const running = document.createElement('span');
    running.className = 'app-badge running';
    running.textContent = 'Aberto';
    meta.append(running);
  }
  if (risk.level !== 'none') {
    const riskBadge = document.createElement('span');
    riskBadge.className = `app-badge ${risk.level}`;
    riskBadge.textContent = risk.label;
    meta.append(riskBadge);
  }
  if (item.source === 'manual') {
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'remove-app';
    remove.textContent = 'Remover';
    remove.disabled = selectiveBusy || selectiveState === 'running';
    remove.addEventListener('click', async event => {
      event.preventDefault();
      event.stopPropagation();
      selectedPaths.delete(item.path.toLowerCase());
      availableApps = availableApps.filter(candidate => candidate.path.toLowerCase() !== item.path.toLowerCase());
      renderAppLists();
      updateSelectedCount();
      await window.ghostRoute.saveSelectedApps(selectedApps());
    });
    meta.append(remove);
  }
  label.append(checkbox, icon, details, meta);
  return label;
}

function renderAppLists() {
  const query = appSearch.value.trim().toLocaleLowerCase('pt-BR');
  const selected = availableApps.filter(item => selectedPaths.has(item.path.toLowerCase()));
  const installed = availableApps.filter(item => !selectedPaths.has(item.path.toLowerCase()) && item.name.toLocaleLowerCase('pt-BR').includes(query));
  selectedAppList.replaceChildren();
  installedAppList.replaceChildren();
  if (!selected.length) {
    const empty = document.createElement('div');
    empty.className = 'app-empty';
    empty.textContent = 'Nenhum aplicativo selecionado.';
    selectedAppList.append(empty);
  }
  selected.forEach(item => selectedAppList.append(createAppItem(item, true)));
  if (!installed.length) {
    const empty = document.createElement('div');
    empty.className = 'app-empty';
    empty.textContent = query ? 'Nenhum aplicativo encontrado.' : 'Nenhum outro aplicativo detectado.';
    installedAppList.append(empty);
  }
  installed.forEach(item => installedAppList.append(createAppItem(item, false)));
}

async function loadApps(savedSelection) {
  selectedPaths = new Set((savedSelection || []).map(item => item.path.toLowerCase()));
  const selectionCountBeforeRiskFilter = selectedPaths.size;
  availableApps = await window.ghostRoute.listApps();
  const blockedPaths = new Set(availableApps.filter(item => item.risk?.level === 'blocked').map(item => item.path.toLowerCase()));
  selectedPaths = new Set([...selectedPaths].filter(itemPath => !blockedPaths.has(itemPath)));
  renderAppLists();
  updateSelectedCount();
  if (selectedPaths.size !== selectionCountBeforeRiskFilter) await window.ghostRoute.saveSelectedApps(selectedApps());
}

function renderIdentity(identity) {
  const exists = Boolean(identity?.exists);
  const active = identity?.status === 'active';
  identityDetails.hidden = !exists;
  identityActivation.hidden = !exists || active;
  copyIdentityButton.hidden = !exists;
  generateIdentityButton.hidden = exists;
  identityPill.textContent = active ? 'Ativa' : (exists ? 'Aguardando cadastro' : 'Não gerada');
  identityPill.className = `mini-pill ${active ? 'running' : (exists ? 'starting' : 'stopped')}`;
  if (exists) {
    identityDevice.textContent = identity.deviceName;
    identityPublicKey.textContent = identity.publicKey;
    identityAddress.value = identity.address || '';
    identityMessage.textContent = active
      ? `Identidade ativa em ${identity.address}. A chave privada permanece protegida pelo Windows.`
      : 'Copie a solicitação para cadastrar somente esta chave pública na VPS.';
  }
}

async function refreshStatus(quiet = false) {
  try {
    const status = await window.ghostRoute.status(configField.value);
    renderStatus(status);
    if (!quiet) showMessage(status.state === 'connected' ? 'Serviço WireGuard em execução.' : 'Túnel desconectado.');
  } catch (error) {
    setUiState('error');
    showMessage(error.message, 'error');
  }
}

selectButton.addEventListener('click', async () => {
  try {
    const selected = await window.ghostRoute.selectConfig();
    if (selected) {
      configField.value = selected;
      showMessage('Configuração local selecionada. A chave privada não será exibida.');
      await refreshStatus(true);
    }
  } catch (error) { showMessage(error.message, 'error'); }
});

connectButton.addEventListener('click', async () => {
  operationInProgress = true;
  setUiState('connecting');
  showMessage('Autorize a instalação do túnel na janela do Windows.');
  let completed = false;
  try {
    const status = await window.ghostRoute.connect(configField.value);
    renderStatus(status);
    if (status.state === 'connected' && status.publicIp) {
      showMessage(`Conectado. IP público: ${status.publicIp}`, 'success');
    } else {
      showMessage('Serviço ativo; aguardando handshake recente com a VPS.');
    }
    completed = true;
  } catch (error) {
    setUiState('error');
    showMessage(error.message, 'error');
  } finally {
    operationInProgress = false;
    if (completed) await refreshStatus(true);
  }
});

disconnectButton.addEventListener('click', async () => {
  operationInProgress = true;
  setUiState('disconnecting');
  showMessage('Autorize a remoção do túnel na janela do Windows.');
  let completed = false;
  try {
    const status = await window.ghostRoute.disconnect(configField.value);
    renderStatus(status);
    publicIp.textContent = '—';
    showMessage('VPN desconectada com segurança.', 'success');
    completed = true;
  } catch (error) {
    setUiState('error');
    showMessage(error.message, 'error');
  } finally {
    operationInProgress = false;
    if (completed) await refreshStatus(true);
  }
});

refreshButton.addEventListener('click', () => refreshStatus());

diagnosticsButton.addEventListener('click', async () => {
  diagnosticsButton.disabled = true;
  showMessage('Testando IPv4, IPv6 e resolução DNS…');
  try {
    const result = await window.ghostRoute.diagnostics();
    if (result.ipv4) publicIp.textContent = result.ipv4;
    dnsStatus.textContent = result.dns?.working
      ? `Funcionando${result.dns.sample ? ` (${result.dns.sample})` : ''}`
      : 'Falha na resolução';
    dnsServers.textContent = result.dnsServers?.length ? result.dnsServers.join(' · ') : 'Não identificados';
    ipv6Status.textContent = result.ipv6 ? `Exposto: ${result.ipv6}` : 'Não detectado';
    diagnosticsTime.textContent = new Date(result.checkedAt).toLocaleTimeString('pt-BR');
    if (!result.dns?.working) {
      showMessage('Diagnóstico incompleto: a resolução DNS do Windows falhou.', 'error');
    } else if (result.ipv6) {
      showMessage('Foi detectado um endereço IPv6 público fora da proteção IPv4.', 'error');
    } else {
      showMessage('Diagnóstico concluído: DNS funcional e nenhum IPv6 público detectado.', 'success');
    }
  } catch (error) {
    showMessage(`Falha no diagnóstico: ${error.message}`, 'error');
  } finally {
    diagnosticsButton.disabled = false;
  }
});

appSearch.addEventListener('input', renderAppLists);

refreshAppsButton.addEventListener('click', async () => {
  refreshAppsButton.disabled = true;
  try { await loadApps(selectedApps()); }
  finally { refreshAppsButton.disabled = false; }
});

addManualAppButton.addEventListener('click', async () => {
  const item = await window.ghostRoute.addManualApp();
  if (!item) return;
  item.risk = item.risk || { level: 'none', label: '' };
  item.running = false;
  if (!availableApps.some(existing => existing.path.toLowerCase() === item.path.toLowerCase())) availableApps.push(item);
  availableApps.sort((left, right) => left.name.localeCompare(right.name, 'pt-BR'));
  if (item.risk.level === 'blocked') {
    renderAppLists();
    setSelectiveState('error', `${item.name} foi identificado como anticheat e não pode ser selecionado.`);
    return;
  }
  selectedPaths.add(item.path.toLowerCase());
  renderAppLists();
  updateSelectedCount();
  await window.ghostRoute.saveSelectedApps(selectedApps());
});

generateIdentityButton.addEventListener('click', async () => {
  generateIdentityButton.disabled = true;
  identityMessage.textContent = 'Gerando e protegendo a identidade local…';
  try {
    renderIdentity(await window.ghostRoute.generateIdentity());
  } catch (error) {
    identityMessage.textContent = cleanErrorMessage(error);
  } finally {
    generateIdentityButton.disabled = false;
  }
});

copyIdentityButton.addEventListener('click', async () => {
  try {
    await window.ghostRoute.copyIdentityRequest();
    identityMessage.textContent = 'Solicitação pública copiada. Nenhuma chave privada foi copiada.';
  } catch (error) {
    identityMessage.textContent = cleanErrorMessage(error);
  }
});

activateIdentityButton.addEventListener('click', async () => {
  activateIdentityButton.disabled = true;
  identityMessage.textContent = 'Ativando a identidade local…';
  try {
    const identity = await window.ghostRoute.activateIdentity(identityAddress.value);
    selectiveConfigReady = true;
    renderIdentity(identity);
    setSelectiveState('stopped');
  } catch (error) {
    identityMessage.textContent = cleanErrorMessage(error);
  } finally {
    activateIdentityButton.disabled = false;
  }
});

startSelectiveButton.addEventListener('click', async () => {
  const chosen = selectedApps();
  const opened = chosen.filter(item => item.running);
  if (opened.length) {
    setSelectiveState('error', `Feche antes de conectar: ${opened.map(item => item.name).join(', ')}.`);
    return;
  }
  const warned = chosen.filter(item => item.risk?.level === 'warning');
  if (warned.length && !window.confirm(`Atenção: ${warned.map(item => item.name).join(', ')} pode ser jogo ou launcher. O GhostRoute não garante compatibilidade com anticheats. Deseja continuar?`)) return;
  selectiveBusy = true;
  setSelectiveState('starting', launchAppsToggle.checked ? 'Configurando o túnel e abrindo os aplicativos selecionados…' : 'Configurando o túnel. Abra os aplicativos depois da conexão…');
  try {
    const result = await window.ghostRoute.startSelective({
      apps: chosen,
      fullTunnelConfigPath: configField.value,
      launchApps: launchAppsToggle.checked
    });
    setSelectiveState('running', result.launchedCount
      ? `${result.launchedCount} aplicativo(s) iniciado(s) pelo túnel via servidor ${result.serverIp}.`
      : `Túnel ativo para ${result.appCount} aplicativo(s). Abra-os agora para usar a rota privada.`);
  } catch (error) {
    setSelectiveState('error', cleanErrorMessage(error));
  } finally {
    selectiveBusy = false;
    setSelectiveState(selectiveState === 'starting' ? 'stopped' : selectiveState);
  }
});

stopSelectiveButton.addEventListener('click', async () => {
  selectiveBusy = true;
  stopSelectiveButton.disabled = true;
  try {
    const result = await window.ghostRoute.stopSelective();
    setSelectiveState('stopped', result.message || 'Modo seletivo encerrado.');
  } catch (error) {
    setSelectiveState('error', cleanErrorMessage(error));
  } finally {
    selectiveBusy = false;
    stopSelectiveButton.disabled = false;
    setSelectiveState(selectiveState);
  }
});

window.ghostRoute.onSelectiveStatus(status => {
  setSelectiveState(status.state, status.message);
});

// Exibe mensagem de erro quando o encerramento falha (ex.: UAC cancelado)
window.ghostRoute.onShutdownFailed(msg => {
  showMessage(`Falha ao encerrar: ${msg} Tente novamente pelo menu da bandeja.`, 'error');
  // Se a janela estava oculta, ela já foi restaurada pelo shutdownController.
});

window.ghostRoute.loadConfig().then(saved => {
  configField.value = saved.wireGuardConfigPath || '';
  selectiveConfigReady = Boolean(saved.selectiveConfigReady);
  setUiState('disconnected');
  if (!selectiveConfigReady) setSelectiveState('error', 'A identidade VPN deste computador ainda não foi provisionada.');
  loadApps(saved.selectedApps).catch(error => setSelectiveState('error', cleanErrorMessage(error)));
  window.ghostRoute.identityStatus().then(renderIdentity).catch(error => { identityMessage.textContent = cleanErrorMessage(error); });
  window.ghostRoute.selectiveStatus().then(status => setSelectiveState(status.state, status.message));
  refreshStatus(true);
});

setInterval(() => {
  if (!operationInProgress && configField.value) refreshStatus(true);
}, 5000);
