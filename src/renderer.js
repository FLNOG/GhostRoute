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
const appList = document.querySelector('#appList');
const addManualAppButton = document.querySelector('#addManualAppButton');
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
  appList.querySelectorAll('input').forEach(input => { input.disabled = blocked; });
  if (text) selectiveMessage.textContent = text;
  connectButton.disabled = running || residual || operationInProgress || !configField.value;
}

function selectedApps() {
  return availableApps.filter(item => selectedPaths.has(item.path.toLowerCase()));
}

function updateSelectedCount() {
  const count = selectedPaths.size;
  selectedCount.textContent = count === 0
    ? 'Nenhum aplicativo selecionado.'
    : `${count} aplicativo${count === 1 ? '' : 's'} selecionado${count === 1 ? '' : 's'}.`;
  setSelectiveState(selectiveState);
}

function renderAppList() {
  const query = appSearch.value.trim().toLocaleLowerCase('pt-BR');
  const visible = availableApps.filter(item => item.name.toLocaleLowerCase('pt-BR').includes(query));
  appList.replaceChildren();
  if (!visible.length) {
    const empty = document.createElement('div');
    empty.className = 'app-empty';
    empty.textContent = query ? 'Nenhum aplicativo encontrado.' : 'Nenhum aplicativo detectado.';
    appList.append(empty);
    return;
  }
  visible.forEach(item => {
    const label = document.createElement('label');
    label.className = 'app-item';
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.checked = selectedPaths.has(item.path.toLowerCase());
    checkbox.disabled = selectiveBusy || selectiveState === 'running';
    checkbox.addEventListener('change', async () => {
      const key = item.path.toLowerCase();
      if (checkbox.checked) selectedPaths.add(key); else selectedPaths.delete(key);
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
    label.append(checkbox, icon, details);
    appList.append(label);
  });
}

async function loadApps(savedSelection) {
  selectedPaths = new Set((savedSelection || []).map(item => item.path.toLowerCase()));
  availableApps = await window.ghostRoute.listApps();
  renderAppList();
  updateSelectedCount();
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

appSearch.addEventListener('input', renderAppList);

addManualAppButton.addEventListener('click', async () => {
  const item = await window.ghostRoute.addManualApp();
  if (!item) return;
  if (!availableApps.some(existing => existing.path.toLowerCase() === item.path.toLowerCase())) availableApps.push(item);
  selectedPaths.add(item.path.toLowerCase());
  availableApps.sort((left, right) => left.name.localeCompare(right.name, 'pt-BR'));
  renderAppList();
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
  selectiveBusy = true;
  setSelectiveState('starting', 'Configurando o túnel e abrindo os aplicativos selecionados…');
  try {
    const result = await window.ghostRoute.startSelective({
      apps: selectedApps(),
      fullTunnelConfigPath: configField.value
    });
    setSelectiveState('running', `${result.appCount} aplicativo(s) iniciado(s) pelo túnel via servidor ${result.serverIp}.`);
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
