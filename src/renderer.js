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
let selectedIds = new Set();  // usa canonicalId, não path
let selectiveConfigReady = false;
let currentFilter = 'all';    // filtro da lista de instalados

// GhostRouteCatalog carregado por catalog-shared.js via <script> em index.html
// Fornece: isValidId, canonicalId, appMatchesFilter, removeFromSelectionWithRollback

function canonicalId(item) {
  return GhostRouteCatalog.canonicalId(item);
}

// Verifica se um item é selecionável (não bloqueado/indisponível)
function isSelectable(item) {
  if (item?.unavailable) return false;
  if (item?.compatibility === 'unsupported') return false;
  if (item?.risk?.level === 'blocked') return false;
  if (!canonicalId(item)) return false;
  return true;
}

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
  startSelectiveButton.disabled = selectiveBusy || !selectiveConfigReady || selectedIds.size === 0;
  appSearch.disabled = blocked;
  addManualAppButton.disabled = blocked;
  document.querySelectorAll('#selectedAppList input, #installedAppList input').forEach(input => { input.disabled = blocked; });
  refreshAppsButton.disabled = blocked;
  launchAppsToggle.disabled = blocked;
  if (text) selectiveMessage.textContent = text;
  connectButton.disabled = running || residual || operationInProgress || !configField.value;
}

function selectedApps() {
  return availableApps.filter(item => {
    const cid = canonicalId(item);
    return cid && selectedIds.has(cid);
  });
}

function selectedAppCanonicalIds() {
  return [...selectedIds].filter(Boolean);
}

function updateSelectedCount() {
  const count = selectedIds.size;
  selectedCount.textContent = count === 0 ? 'Nenhum selecionado' : `${count} selecionado${count === 1 ? '' : 's'}`;
  setSelectiveState(selectiveState);
}

function createAppItem(item, selected) {
  const risk = item.risk || { level: 'none', label: '' };
  const blocked = risk.level === 'blocked' || item.unavailable || item.compatibility === 'unsupported';
  const selectable = isSelectable(item);
  const cid = canonicalId(item);

  const label = document.createElement('label');
  label.className = [
    'app-item',
    blocked ? 'blocked' : '',
    item.unavailable ? 'unavailable' : '',
    item.compatibility === 'unsupported' && !item.unavailable ? 'unsupported' : '',
  ].filter(Boolean).join(' ');

  const checkbox = document.createElement('input');
  checkbox.type = 'checkbox';
  checkbox.checked = selected;
  checkbox.disabled = !selectable || selectiveBusy || selectiveState === 'running';
  checkbox.addEventListener('change', async () => {
    if (!cid) return;
    if (checkbox.checked) selectedIds.add(cid); else selectedIds.delete(cid);
    renderAppLists();
    updateSelectedCount();
    await window.ghostRoute.saveSelectedApps(selectedAppCanonicalIds());
  });

  const icon = item.icon ? document.createElement('img') : document.createElement('span');
  if (item.icon) { icon.src = item.icon; icon.alt = ''; }
  else { icon.className = 'app-fallback'; icon.textContent = item.name.slice(0, 1).toUpperCase(); }

  const details = document.createElement('span');
  details.className = 'app-details';
  const name = document.createElement('strong');
  name.textContent = item.name;
  const appPath = document.createElement('small');
  appPath.textContent = item.kind === 'uwp' ? (item.appUserModelId || '') : (item.path || '');
  details.append(name, appPath);

  // Se não selecionável: motivo
  if (!selectable) {
    const reason = document.createElement('small');
    reason.className = 'app-reason';
    reason.textContent = item.unavailable
      ? `Não encontrado: ${item.unavailableReason || 'arquivo ausente'}`
      : item.compatibility === 'unsupported'
        ? 'Não compatível com roteamento seletivo'
        : risk.label || 'Bloqueado';
    details.append(reason);
  }

  // Badges
  const meta = document.createElement('span');
  meta.className = 'app-meta';

  // Kind badge
  if (item.kind === 'uwp') {
    const b = document.createElement('span'); b.className = 'app-badge store'; b.textContent = 'Store';
    meta.append(b);
    if (item.compatibility === 'experimental') {
      const e = document.createElement('span'); e.className = 'app-badge experimental'; e.textContent = 'Experimental';
      meta.append(e);
    }
  }
  if (item.source === 'manual') {
    const b = document.createElement('span'); b.className = 'app-badge manual'; b.textContent = 'Manual';
    meta.append(b);
  }
  if (item.unavailable) {
    const b = document.createElement('span'); b.className = 'app-badge unavailable'; b.textContent = 'Não encontrado';
    meta.append(b);
  }
  if (item.running || item.runningState === 'running') {
    const b = document.createElement('span'); b.className = 'app-badge running'; b.textContent = 'Aberto';
    meta.append(b);
  }
  if (item.isLauncher) {
    const b = document.createElement('span'); b.className = 'app-badge launcher'; b.textContent = 'Launcher';
    meta.append(b);
  }
  if (risk.level !== 'none') {
    const b = document.createElement('span'); b.className = `app-badge ${risk.level}`; b.textContent = risk.label;
    meta.append(b);
  }

  // Botão remover (itens manuais)
  if (item.source === 'manual') {
    const remove = document.createElement('button');
    remove.type = 'button'; remove.className = 'remove-app'; remove.textContent = 'Remover';
    remove.disabled = selectiveBusy || selectiveState === 'running';
    remove.addEventListener('click', async event => {
      event.preventDefault(); event.stopPropagation();
      if (!cid) return;
      try {
        const result = await window.ghostRoute.removeManualApp(cid);
        if (result && result.removed) {
          selectedIds.delete(cid);
          availableApps = availableApps.filter(candidate => canonicalId(candidate) !== cid);
          renderAppLists(); updateSelectedCount();
        }
      } catch (err) { showMessage(cleanErrorMessage(err), 'error'); }
    });
    meta.append(remove);
  }

  // Botão "Remover da seleção" para itens selecionados mas não selecionáveis
  // (indisponíveis, incompatíveis ou bloqueados): evita checkbox preso
  if (selected && !selectable && cid) {
    const removeFromSel = document.createElement('button');
    removeFromSel.type = 'button'; removeFromSel.className = 'remove-app ghost small';
    removeFromSel.textContent = 'Remover da seleção';
    removeFromSel.addEventListener('click', async event => {
      event.preventDefault(); event.stopPropagation();
      // Usa removeFromSelectionWithRollback de catalog-shared: não muta selectedIds antes de persistir
      const result = await GhostRouteCatalog.removeFromSelectionWithRollback(
        selectedIds, cid,
        ids => window.ghostRoute.saveSelectedApps(ids)
      );
      selectedIds.clear();
      for (const id of result.ids) selectedIds.add(id);
      renderAppLists(); updateSelectedCount();
      if (!result.committed) showMessage(cleanErrorMessage(result.error), 'error');
    });
    meta.append(removeFromSel);
  }

  // Botão launcher: escolher executável real
  if (item.isLauncher) {
    const chooseBtn = document.createElement('button');
    chooseBtn.type = 'button'; chooseBtn.className = 'choose-real-app ghost small';
    chooseBtn.textContent = 'Escolher executável real';
    chooseBtn.disabled = selectiveBusy || selectiveState === 'running';
    chooseBtn.addEventListener('click', async event => {
      event.preventDefault(); event.stopPropagation();
      try {
        const newItem = await window.ghostRoute.addManualApp();
        if (!newItem) return;
        const newCid = canonicalId(newItem);
        if (!newCid) return;
        if (!availableApps.find(a => canonicalId(a) === newCid)) {
          availableApps.push(newItem);
          availableApps.sort((a, b) => a.name.localeCompare(b.name, 'pt-BR'));
        }
        renderAppLists(); updateSelectedCount();
      } catch (err) {
        showMessage(cleanErrorMessage(err), 'error');
      }
    });
    if (item.launcherNote) {
      const note = document.createElement('small'); note.className = 'launcher-note'; note.textContent = item.launcherNote;
      details.append(note);
    }
    meta.append(chooseBtn);
  }

  label.append(checkbox, icon, details, meta);
  return label;
}

function renderAppLists() {
  const query = appSearch.value.trim().toLocaleLowerCase('pt-BR');
  const isSelected = item => { const cid = canonicalId(item); return cid && selectedIds.has(cid); };
  const selected   = availableApps.filter(isSelected);
  const installed  = availableApps.filter(item => {
    if (isSelected(item)) return false;
    // Aplica filtro atual + busca
    return matchesCurrentFilter(item, query);
  });

  selectedAppList.replaceChildren();
  installedAppList.replaceChildren();

  if (!selected.length) {
    const empty = document.createElement('div'); empty.className = 'app-empty';
    empty.textContent = 'Nenhum aplicativo selecionado.';
    selectedAppList.append(empty);
  }
  selected.forEach(item => selectedAppList.append(createAppItem(item, true)));

  if (!installed.length) {
    const empty = document.createElement('div'); empty.className = 'app-empty';
    empty.textContent = query || currentFilter !== 'all' ? 'Nenhum aplicativo encontrado.' : 'Nenhum outro aplicativo detectado.';
    installedAppList.append(empty);
  }
  installed.forEach(item => installedAppList.append(createAppItem(item, false)));
}

function matchesCurrentFilter(item, query) {
  // Delega para catalog-shared.js (namespace GhostRouteCatalog) — única implementação.
  return GhostRouteCatalog.appMatchesFilter(item, currentFilter, query);
}

async function loadApps(savedIds) {
  // savedIds: array de canonical IDs salvos
  selectedIds = new Set((savedIds || []).filter(Boolean));
  availableApps = await window.ghostRoute.listApps();
  // Remover da seleção itens bloqueados por risco
  const selectionCountBefore = selectedIds.size;
  for (const item of availableApps) {
    if (item.risk?.level === 'blocked') {
      const cid = canonicalId(item);
      if (cid) selectedIds.delete(cid);
    }
  }
  renderAppLists();
  updateSelectedCount();
  if (selectedIds.size !== selectionCountBefore) {
    await window.ghostRoute.saveSelectedApps(selectedAppCanonicalIds());
  }
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

// Filtros de categoria
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentFilter = btn.dataset.filter || 'all';
    renderAppLists();
  });
});

refreshAppsButton.addEventListener('click', async () => {
  refreshAppsButton.disabled = true;
  try { await loadApps(selectedAppCanonicalIds()); }
  finally { refreshAppsButton.disabled = false; }
});

addManualAppButton.addEventListener('click', async () => {
  try {
    const item = await window.ghostRoute.addManualApp();
    if (!item) return;
    const cid = canonicalId(item);
    if (!cid) return;
    if (!availableApps.find(a => canonicalId(a) === cid)) availableApps.push(item);
    availableApps.sort((l, r) => l.name.localeCompare(r.name, 'pt-BR'));
    if (item.risk?.level === 'blocked') {
      renderAppLists();
      setSelectiveState('error', `${item.name} foi identificado como anticheat e não pode ser selecionado.`);
      return;
    }
    if (isSelectable(item)) selectedIds.add(cid);
    renderAppLists(); updateSelectedCount();
    await window.ghostRoute.saveSelectedApps(selectedAppCanonicalIds());
  } catch (err) { showMessage(cleanErrorMessage(err), 'error'); }
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
      apps: selectedAppCanonicalIds(),
      fullTunnelConfigPath: configField.value,
      launchApps: launchAppsToggle.checked
    });
    const launchMsg = [];
    if (result.launchedCount) launchMsg.push(`${result.launchedCount} aberto(s)`);
    if (result.manualLaunchCount) launchMsg.push(`${result.manualLaunchCount} manual(is)`);
    if (result.uwpLaunchCount) launchMsg.push(`${result.uwpLaunchCount} Store`);
    const msgSuffix = launchMsg.length ? launchMsg.join(', ') + '.' : `Abra os apps manualmente para usar o túnel.`;
    setSelectiveState('running', `Túnel ativo para ${result.appCount} app(s). ${msgSuffix}`);
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
  // Usa selectedAppIds (novo formato) com fallback para selectedApps antigo
  const savedIds = Array.isArray(saved.selectedAppIds)
    ? saved.selectedAppIds
    : (Array.isArray(saved.selectedApps) ? saved.selectedApps.map(a => a?.id || a?.path?.toLowerCase()).filter(Boolean) : []);
  loadApps(savedIds).catch(error => setSelectiveState('error', cleanErrorMessage(error)));
  window.ghostRoute.identityStatus().then(renderIdentity).catch(error => { identityMessage.textContent = cleanErrorMessage(error); });
  window.ghostRoute.selectiveStatus().then(status => setSelectiveState(status.state, status.message));
  refreshStatus(true);
});

setInterval(() => {
  if (!operationInProgress && configField.value) refreshStatus(true);
}, 5000);
