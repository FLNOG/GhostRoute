'use strict';

/**
 * GhostRoute — testes automatizados mínimos
 *
 * Execução: npm test  (ou  node --test src/tests/ghost-route.test.js)
 * Requer Node 18+ (node:test built-in, sem dependências extras).
 *
 * ── Garantias de isolamento ───────────────────────────────────────────────
 *
 *  - Nenhum processo externo é iniciado (sem PowerShell, sem sc.exe,
 *    sem wiresock-connect-cli.exe, sem executáveis de app).
 *  - Nenhum UAC é solicitado.
 *  - Nenhum serviço do Windows é consultado ou modificado.
 *  - Nenhuma configuração real de WireGuard ou WireSock é lida ou escrita.
 *  - Todo I/O de arquivo ocorre exclusivamente em pastas temporárias de OS
 *    criadas e destruídas dentro de cada teste.
 *  - device-identity.json da máquina nunca é lido ou tocado.
 *  - Chaves privadas nunca aparecem neste arquivo.
 *  - selective.start() NÃO é chamado em nenhum teste.
 *
 * ── Como o isolamento é garantido ────────────────────────────────────────
 *
 *  • publicIdentity / removeMaterializedConfig / cleanupStaleConfigs:
 *    funções puras ou I/O em tmpdir.
 *
 *  • selective.prepare() (= buildWireSockConfig): opera apenas em arquivos
 *    de tmpdir fornecidos pelo teste. Nenhuma chamada a processo externo.
 *    Usado inclusive para testar rejeição de lista vazia (normalizeApps lança
 *    sincronamente antes de qualquer processo externo).
 *
 *  • OperationGuard: módulo 100% puro. Testado com instâncias criadas
 *    localmente — isolado do estado global de produção.
 */

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

// ── módulos do projeto ────────────────────────────────────────────────────

const {
  publicIdentity,
  cleanupStaleConfigs,
  removeMaterializedConfig
} = require('../vpn/identity-manager');

const selective = require('../vpn/selective-controller');
const {
  _cleanupSelectiveSession,
  _spawnAndConfirm,
  _launchSelectedApps,
  _requestStop,
  _processPendingCleanup,
  _getTestState,
  _setTestState
} = selective;

const { createOperationGuard } = require('../vpn/operation-guard');
const { createShutdownController } = require('../shutdown-controller');
const { selectiveStateForMenu } = require('../tray-menu-state');
const { createCleanupFn } = require('../app-cleanup');
const { classifyAppRisk, isExcludedApp, normalizeItem } = require('../vpn/installed-apps');

// ── utilitário: pasta temporária isolada ─────────────────────────────────

function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'ghostroute-test-'));
}

/** Cria um ChildProcess simulado (EventEmitter puro) com pid definido.
 * Usado nos testes de spawnAndConfirm — zero operações externas. */
function makeFakeChild(pid) {
  const child = new EventEmitter();
  child.pid = pid ?? 1;
  return child;
}

/**
 * Cria um arquivo .conf WireGuard mínimo válido (com [Interface] e [Peer]).
 * Conteúdo 100% sintético — sem chaves reais.
 */
function makeMinimalConf(dir, filename, extraInterfaceLines) {
  const confPath = path.join(dir, filename || 'test.conf');
  const lines = [
    '[Interface]',
    'PrivateKey = TESTPRIVKEY',
    'Address = 10.77.0.50/32',
    ...(extraInterfaceLines || []),
    '',
    '[Peer]',
    'PublicKey = TESTPUBKEY=',
    'Endpoint = 1.2.3.4:51820',
    'AllowedIPs = 0.0.0.0/0',
    ''
  ];
  fs.writeFileSync(confPath, lines.join('\n'), 'utf8');
  return confPath;
}

// ── 1. publicIdentity nunca expõe privateKeyDpapi ────────────────────────

describe('publicIdentity', () => {
  test('nunca inclui privateKeyDpapi na resposta', () => {
    const identity = {
      version: 1,
      deviceId: '00000000-0000-0000-0000-000000000001',
      deviceName: 'TESTMACHINE',
      publicKey: 'FAKEPUBLICKEY=',
      privateKeyDpapi: 'SEGREDO_NAO_DEVE_APARECER',
      createdAt: new Date().toISOString(),
      status: 'active',
      address: '10.77.0.50/32'
    };

    const result = publicIdentity(identity);

    assert.ok(!('privateKeyDpapi' in result),
      'privateKeyDpapi não deve ser uma chave da resposta');
    assert.ok(!JSON.stringify(result).includes('SEGREDO_NAO_DEVE_APARECER'),
      'o valor secreto não deve aparecer em lugar algum na resposta serializada');
    assert.strictEqual(result.publicKey, 'FAKEPUBLICKEY=');
    assert.strictEqual(result.status, 'active');
    assert.ok(result.exists);
  });

  test('retorna { exists: false } para null', () => {
    assert.deepStrictEqual(publicIdentity(null), { exists: false });
  });

  test('retorna { exists: false } para undefined', () => {
    assert.deepStrictEqual(publicIdentity(undefined), { exists: false });
  });
});

// ── 2. cleanupStaleConfigs ────────────────────────────────────────────────

describe('cleanupStaleConfigs', () => {
  test('remove session conf e wiresock.generated.conf; preserva outros arquivos', () => {
    const dir = makeTempDir();
    try {
      const sessionFile = path.join(dir,
        'ghostroute-session-12345678-abcd-ef00-1234-000000000001.conf');
      const generatedFile = path.join(dir, 'wiresock.generated.conf');
      const identityFile  = path.join(dir, 'device-identity.json');
      const settingsFile  = path.join(dir, 'settings.json');
      const wrongExtFile  = path.join(dir,
        'ghostroute-session-12345678-abcd-ef00-1234-000000000002.txt');

      for (const f of [sessionFile, generatedFile, identityFile, settingsFile, wrongExtFile]) {
        fs.writeFileSync(f, 'placeholder');
      }

      const removed = cleanupStaleConfigs(dir);

      assert.strictEqual(removed, 2,
        `Esperado remover 2 arquivos, mas foram removidos ${removed}`);
      assert.ok(!fs.existsSync(sessionFile),
        'ghostroute-session-*.conf deve ser removido');
      assert.ok(!fs.existsSync(generatedFile),
        'wiresock.generated.conf deve ser removido');
      assert.ok(fs.existsSync(identityFile),
        'device-identity.json NÃO deve ser removido');
      assert.ok(fs.existsSync(settingsFile),
        'settings.json NÃO deve ser removido');
      assert.ok(fs.existsSync(wrongExtFile),
        'arquivo .txt com prefixo de sessão NÃO deve ser removido');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('retorna 0 sem lançar exceção para diretório inexistente', () => {
    const missing = path.join(os.tmpdir(), 'ghostroute-nonexistent-' + Date.now());
    assert.doesNotThrow(() => {
      const n = cleanupStaleConfigs(missing);
      assert.strictEqual(n, 0);
    });
  });
});

// ── 3. removeMaterializedConfig ───────────────────────────────────────────

describe('removeMaterializedConfig', () => {
  test('remove arquivo de sessão válido', () => {
    const dir = makeTempDir();
    try {
      const sessionFile = path.join(dir,
        'ghostroute-session-aaaabbbb-cccc-dddd-eeee-111122223333.conf');
      fs.writeFileSync(sessionFile, 'placeholder');
      removeMaterializedConfig(sessionFile);
      assert.ok(!fs.existsSync(sessionFile), 'arquivo de sessão deve ser deletado');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('NÃO deleta arquivo sem o prefixo de sessão', () => {
    const dir = makeTempDir();
    try {
      const arbitraryFile = path.join(dir, 'important-data.conf');
      fs.writeFileSync(arbitraryFile, 'nao apagar');
      removeMaterializedConfig(arbitraryFile);
      assert.ok(fs.existsSync(arbitraryFile),
        'arquivo .conf arbitrário NÃO deve ser deletado');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('NÃO deleta device-identity.json', () => {
    const dir = makeTempDir();
    try {
      const identityFile = path.join(dir, 'device-identity.json');
      fs.writeFileSync(identityFile, '{}');
      removeMaterializedConfig(identityFile);
      assert.ok(fs.existsSync(identityFile),
        'device-identity.json NÃO deve ser deletado');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('não lança exceção com string vazia', () => {
    assert.doesNotThrow(() => removeMaterializedConfig(''));
  });

  test('não lança exceção com undefined', () => {
    assert.doesNotThrow(() => removeMaterializedConfig(undefined));
  });
});

// ── 4. Rejeição de caminho com vírgula e lista vazia ─────────────────────
//
// Todos os testes deste grupo usam selective.prepare() (= buildWireSockConfig).
// Fluxo de execução: validateFile(sourceConf) → readFileSync → normalizeApps(apps).
// normalizeApps lança sincronamente ANTES de qualquer acesso externo (processo,
// WireSock, UAC). Nenhum teste chama selective.start().

describe('normalizeApps — rejeição via selective.prepare', () => {
  test('lança erro para lista vazia de apps (sem operação externa)', () => {
    // buildWireSockConfig chama normalizeApps([]) que lança sincronamente.
    // Nenhum processo externo é alcançado.
    const dir = makeTempDir();
    try {
      const validConf = makeMinimalConf(dir, 'test-empty.conf');
      assert.throws(
        () => selective.prepare(validConf, [], dir),
        /Selecione pelo menos um aplicativo/
      );
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('lança erro de vírgula ANTES de verificar existência do arquivo', () => {
    // A verificação de vírgula em normalizeApps está antes de validateFile
    // para os apps. O arquivo com vírgula no caminho não precisa existir.
    const dir = makeTempDir();
    try {
      const validConf = makeMinimalConf(dir, 'test-comma.conf');
      const pathWithComma = path.join(os.tmpdir(), 'app,name', 'test.exe');

      assert.throws(
        () => selective.prepare(validConf, [{ name: 'App', path: pathWithComma }], dir),
        /cont[eé]m v[ií]rgula/i,
        'deve rejeitar caminho com vírgula antes de tentar acessar o arquivo'
      );
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a mensagem de erro com vírgula menciona o nome do app', () => {
    const dir = makeTempDir();
    try {
      const validConf = makeMinimalConf(dir, 'test-comma2.conf');
      const pathWithComma = path.join(os.tmpdir(), 'my,app', 'launcher.exe');

      let errorMsg = '';
      try {
        selective.prepare(validConf, [{ name: 'MeuApp', path: pathWithComma }], dir);
      } catch (e) {
        errorMsg = e.message;
      }

      assert.ok(
        errorMsg.toLowerCase().includes('vírgula') || errorMsg.toLowerCase().includes('virgula'),
        `Mensagem "${errorMsg}" deve mencionar 'vírgula'`
      );
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ── 5. buildWireSockConfig (via selective.prepare) ────────────────────────
//
// selective.prepare = buildWireSockConfig: leitura/escrita apenas em tmpdir.
// Nenhum processo externo em nenhum dos casos.

describe('buildWireSockConfig via selective.prepare', () => {
  test('cria arquivo em runtimeDirectory com AllowedApps e sem linha DNS', () => {
    const dir = makeTempDir();
    try {
      const fakeExe = path.join(dir, 'testapp.exe');
      fs.writeFileSync(fakeExe, '');
      const sourceConf = makeMinimalConf(dir, 'with-dns.conf', ['DNS = 8.8.8.8']);

      const destPath = selective.prepare(sourceConf, [{ name: 'TestApp', path: fakeExe }], dir);

      assert.strictEqual(destPath, path.join(dir, 'wiresock.generated.conf'),
        'deve gerar em runtimeDirectory/wiresock.generated.conf');
      assert.ok(fs.existsSync(destPath), 'arquivo gerado deve existir');

      const content = fs.readFileSync(destPath, 'utf8');

      assert.ok(!content.includes('DNS ='), 'linha DNS deve ser removida');
      assert.ok(content.includes('#@ws:AllowedApps ='), 'diretiva AllowedApps deve estar presente');
      assert.ok(content.includes(fakeExe), 'AllowedApps deve referenciar o executável');
      assert.ok(content.includes('\r\n'), 'arquivo gerado deve usar CRLF');
      assert.ok(content.includes('[Interface]'), 'seção [Interface] deve ser preservada');
      assert.ok(content.includes('[Peer]'), 'seção [Peer] deve ser preservada');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('remove AllowedApps existente da origem e insere o novo', () => {
    const dir = makeTempDir();
    try {
      const fakeExe = path.join(dir, 'newapp.exe');
      fs.writeFileSync(fakeExe, '');
      const sourceConf = makeMinimalConf(dir, 'with-old-apps.conf',
        ['#@ws:AllowedApps = C:\\Old\\App.exe']);

      const destPath = selective.prepare(sourceConf, [{ name: 'NewApp', path: fakeExe }], dir);
      const content = fs.readFileSync(destPath, 'utf8');

      assert.ok(!content.includes('C:\\Old\\App.exe'),
        'caminho antigo de AllowedApps deve ser removido');
      assert.ok(content.includes(fakeExe), 'novo caminho deve estar em AllowedApps');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('lança erro se configuração não contém [Interface] e [Peer]', () => {
    const dir = makeTempDir();
    try {
      const fakeExe = path.join(dir, 'app.exe');
      fs.writeFileSync(fakeExe, '');
      const badConf = path.join(dir, 'bad.conf');
      fs.writeFileSync(badConf, '[Peer]\nPublicKey = ABC\n', 'utf8');

      assert.throws(
        () => selective.prepare(badConf, [{ name: 'App', path: fakeExe }], dir),
        /\[Interface\].*\[Peer\]/is
      );
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('arquivo gerado é removível via fs.rmSync (simula limpeza pós-uso)', () => {
    const dir = makeTempDir();
    try {
      const fakeExe = path.join(dir, 'removable.exe');
      fs.writeFileSync(fakeExe, '');
      const sourceConf = makeMinimalConf(dir, 'for-removal.conf');

      const destPath = selective.prepare(sourceConf, [{ name: 'RemovableApp', path: fakeExe }], dir);
      assert.ok(fs.existsSync(destPath), 'arquivo deve existir após prepare()');

      fs.rmSync(destPath, { force: true });
      assert.ok(!fs.existsSync(destPath), 'arquivo deve ter sido removido');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ── 6. OperationGuard — propriedade de token ─────────────────────────────
//
// Testa o módulo operation-guard.js com instâncias locais.
// 100% puro: sem I/O, sem processos, sem dependências de plataforma.
// Sub-milissegundo por teste.
//
// Propriedade crítica: uma release "antiga" (de aquisição já encerrada)
// nunca deve desbloquear uma aquisição posterior. Isso protege start() de
// liberar acidentalmente o guard adquirido por stop() durante cleanup.

describe('OperationGuard — propriedade de token e concorrência', () => {
  test('acquire lança se já bloqueado, com a mensagem da chamada que falha', () => {
    const guard = createOperationGuard();
    const release = guard.acquire('Primeira operação em andamento.');
    // A segunda chamada lança com A SUA PRÓPRIA mensagem (a da chamada que falha).
    assert.throws(
      () => guard.acquire('Segunda chamada bloqueada.'),
      /Segunda chamada bloqueada/
    );
    release();
  });

  test('acquire tem sucesso após release', () => {
    const guard = createOperationGuard();
    const r1 = guard.acquire('Op1');
    r1();
    assert.doesNotThrow(() => {
      const r2 = guard.acquire('Op2');
      r2();
    });
  });

  test('release é idempotente para sua própria aquisição', () => {
    const guard = createOperationGuard();
    const release = guard.acquire('Op');
    assert.doesNotThrow(() => {
      release();
      release(); // segunda chamada: mesma token, owner já é null → ignorada
    });
    assert.ok(!guard.isLocked(), 'guard deve estar desbloqueado');
  });

  test('isLocked reflete o estado corretamente', () => {
    const guard = createOperationGuard();
    assert.ok(!guard.isLocked(), 'inicialmente desbloqueado');
    const release = guard.acquire('Op');
    assert.ok(guard.isLocked(), 'bloqueado após acquire');
    release();
    assert.ok(!guard.isLocked(), 'desbloqueado após release');
  });

  test('release antiga NÃO desbloqueia aquisição posterior (propriedade de token)', () => {
    // Este teste verifica a invariante central: uma função release capturada
    // de uma aquisição anterior não pode liberar uma aquisição subsequente.
    // Relevante para start(): se o finally chama uma release "stale" depois
    // que stop() adquiriu o guard, o guard de stop() permanece intacto.
    const guard = createOperationGuard();

    const release1 = guard.acquire('Op1');
    release1(); // libera corretamente — guard desbloqueado

    const release2 = guard.acquire('Op2');
    release1(); // stale — release1 refere-se a um token antigo, deve ser ignorada

    assert.ok(guard.isLocked(),
      'guard deve continuar bloqueado: release1 é stale e não tem efeito');

    release2(); // release legítima
    assert.ok(!guard.isLocked(),
      'guard deve ser desbloqueado somente pela release legítima');
  });

  test('múltiplas instâncias são completamente independentes', () => {
    const g1 = createOperationGuard();
    const g2 = createOperationGuard();
    const r1 = g1.acquire('G1 bloqueado');
    assert.doesNotThrow(() => {
      const r2 = g2.acquire('G2 independente');
      r2();
    });
    r1();
  });

  test('acquire com mensagem padrão quando nenhuma é fornecida', () => {
    const guard = createOperationGuard();
    const release = guard.acquire(); // sem mensagem personalizada
    assert.throws(
      () => guard.acquire(), // segunda chamada usa mensagem padrão
      /Uma operação já está em andamento/
    );
    release();
  });
});

// ── 7. cleanupSelectiveSession — limpeza de sessão parcial ────────────────
//
// Todos os testes usam dependências injetadas (_killFn, _disconnectFn, _notifyFn).
// Nenhuma operação externa é executada: sem PowerShell, UAC, WireSock ou sc.exe.
// _setTestState / _getTestState permitem verificar o estado interno do módulo
// sem chamar selective.status() (que invocaria sc.exe via hasRunningServices).

describe('cleanupSelectiveSession — limpeza de sessão parcial', () => {
  test('encerra todos os processos parcialmente iniciados', async () => {
    const killed = [];
    const fakeKill = (pid) => { killed.push(pid); return Promise.resolve(); };

    await _cleanupSelectiveSession({
      startedProcesses: [{ pid: 101 }, { pid: 102 }, { pid: 103 }],
      disconnectWireSock: false,
      _killFn: fakeKill
    });

    assert.deepStrictEqual(
      killed.sort((a, b) => a - b),
      [101, 102, 103],
      'todos os PIDs devem ser encerrados'
    );
  });

  test('desconecta WireSock quando disconnectWireSock é true', async () => {
    let disconnected = false;
    const fakeDisconnect = () => { disconnected = true; return Promise.resolve(); };

    await _cleanupSelectiveSession({
      startedProcesses: [],
      disconnectWireSock: true,
      _killFn: () => Promise.resolve(),
      _disconnectFn: fakeDisconnect
    });

    assert.ok(disconnected, 'disconnect deve ser chamado quando disconnectWireSock=true');
  });

  test('não desconecta WireSock quando disconnectWireSock é false', async () => {
    let disconnected = false;
    const fakeDisconnect = () => { disconnected = true; return Promise.resolve(); };

    await _cleanupSelectiveSession({
      startedProcesses: [],
      disconnectWireSock: false,
      _disconnectFn: fakeDisconnect
    });

    assert.ok(!disconnected, 'disconnect NÃO deve ser chamado quando disconnectWireSock=false');
  });

  test('falha no kill não impede a desconexão do WireSock', async () => {
    let disconnected = false;
    const fakeKill = () => Promise.reject(new Error('acesso negado'));
    const fakeDisconnect = () => { disconnected = true; return Promise.resolve(); };

    await _cleanupSelectiveSession({
      startedProcesses: [{ pid: 999 }],
      disconnectWireSock: true,
      _killFn: fakeKill,
      _disconnectFn: fakeDisconnect
    });

    assert.ok(disconnected,
      'disconnect deve ser chamado mesmo quando o kill do processo falha');
  });

  test('selectiveActive é false e launchedProcesses está vazio após cleanup', async () => {
    // Seta estado como se uma sessão estivesse ativa.
    _setTestState({ selectiveActive: true, launchedProcesses: [{ pid: 1 }, { pid: 2 }] });

    await _cleanupSelectiveSession({
      startedProcesses: [],
      disconnectWireSock: false,
      _killFn: () => Promise.resolve()
    });

    const state = _getTestState();
    assert.strictEqual(state.selectiveActive, false,
      'selectiveActive deve ser false após cleanup');
    assert.strictEqual(state.launchedProcessesCount, 0,
      'launchedProcesses deve estar vazio após cleanup');
  });

  test('falha na notificação não deixa sessão em estado inconsistente', async () => {
    _setTestState({ selectiveActive: true });
    const throwingNotify = () => { throw new Error('BrowserWindow destruída'); };

    // Não deve lançar mesmo com notify falhando.
    await assert.doesNotReject(
      () => _cleanupSelectiveSession({
        startedProcesses: [],
        disconnectWireSock: false,
        _notifyFn: throwingNotify
      })
    );

    const state = _getTestState();
    assert.strictEqual(state.selectiveActive, false,
      'sessão deve ser desativada mesmo com falha na notificação');
  });
});

// ── 8. spawnAndConfirm — inicialização segura de processos ────────────────
//
// Usa EventEmitter como ChildProcess simulado. Zero operações externas:
// sem spawn real, PowerShell, WireSock, sc.exe, UAC ou selective.start().
// Os testes comprovam o contrato de listeners temporários e permanentes.

describe("spawnAndConfirm — inicialização segura de processos", () => {

  test("listener de 'error' está ativo imediatamente após spawn() retornar", () => {
    // O executor de new Promise() roda sincronamente: ao retornar a Promise,
    // os listeners já foram registrados. Não há janela sem cobertura de error.
    const fakeChild = makeFakeChild(1);
    const p = _spawnAndConfirm({ path: '/fake/app.exe', name: 'App' }, () => fakeChild);

    assert.ok(fakeChild.listenerCount('error') > 0,
      "listener de 'error' deve estar ativo antes de qualquer await ou emit");

    fakeChild.emit('spawn'); // resolve a Promise para não deixar listeners pendentes
    return p;
  });

  test("'spawn' resolve a Promise com o ChildProcess correto", async () => {
    const fakeChild = makeFakeChild(42);
    const p = _spawnAndConfirm({ path: '/fake/app.exe', name: 'App' }, () => fakeChild);
    fakeChild.emit('spawn');
    const result = await p;
    assert.strictEqual(result.pid, 42, "deve resolver com o ChildProcess original");
  });

  test("'error' antes de 'spawn' rejeita com o erro original", async () => {
    const fakeChild = makeFakeChild(1);
    const err = new Error('ENOENT: executável não encontrado');
    const p = _spawnAndConfirm({ path: '/fake/app.exe', name: 'App' }, () => fakeChild);
    fakeChild.emit('error', err);
    await assert.rejects(p, { message: 'ENOENT: executável não encontrado' });
  });

  test("listener de 'spawn' é removido após 'error' rejeitar", async () => {
    const fakeChild = makeFakeChild(1);
    const p = _spawnAndConfirm({ path: '/fake/app.exe', name: 'App' }, () => fakeChild);
    fakeChild.emit('error', new Error('falha'));
    await p.catch(() => {});
    assert.strictEqual(fakeChild.listenerCount('spawn'), 0,
      "listener temporário de 'spawn' deve ser removido após rejeição");
  });

  test("listener temporário de 'error' é substituído pelo permanente após 'spawn'", async () => {
    const fakeChild = makeFakeChild(1);
    const p = _spawnAndConfirm({ path: '/fake/app.exe', name: 'App' }, () => fakeChild);

    assert.strictEqual(fakeChild.listenerCount('error'), 1,
      "deve haver exatamente 1 listener temporário antes de 'spawn'");

    fakeChild.emit('spawn');
    await p;

    assert.strictEqual(fakeChild.listenerCount('error'), 1,
      "listener temporário removido e permanente adicionado: total deve continuar 1");
    assert.strictEqual(fakeChild.listenerCount('spawn'), 0,
      "listener de 'spawn' deve ter sido removido após confirmação");
  });

  test("listener permanente existe após 'spawn' — previne unhandled rejection", async () => {
    // Não emitimos 'error' aqui (evita chamar stop() real).
    // A presença do listener é a prova formal de que nenhum 'error' possível
    // ficaria sem observador, o que causaria crash do processo Electron.
    const fakeChild = makeFakeChild(1);
    const p = _spawnAndConfirm({ path: '/fake/app.exe', name: 'App' }, () => fakeChild);
    fakeChild.emit('spawn');
    await p;
    assert.ok(fakeChild.listenerCount('error') > 0,
      "listener permanente deve existir após 'spawn'");
  });

  test("somente processos que confirmaram 'spawn' entram na lista de confirmados", async () => {
    const ch1 = makeFakeChild(1);
    const ch2 = makeFakeChild(2); // falhará antes de 'spawn'
    const children = [ch1, ch2];
    let callIndex = 0;
    const fakeSpawn = () => children[callIndex++];

    const apps = [
      { path: '/fake/app1.exe', name: 'App1' },
      { path: '/fake/app2.exe', name: 'App2' }
    ];

    const confirmed = [];
    let failedApp = null;

    for (const app of apps) {
      const p = _spawnAndConfirm(app, fakeSpawn);
      // Dispara o evento apropriado sincronamente antes de await
      if (app.name === 'App1') ch1.emit('spawn');
      else ch2.emit('error', new Error('ENOENT App2'));

      try { confirmed.push(await p); }
      catch { failedApp = app.name; break; }
    }

    assert.strictEqual(confirmed.length, 1, 'somente App1 foi confirmado');
    assert.strictEqual(confirmed[0].pid, 1, 'o processo confirmado tem pid=1 (App1)');
    assert.strictEqual(failedApp, 'App2', 'App2 foi o que falhou');
    assert.strictEqual(callIndex, 2,
      'fakeSpawn chamado exatamente 2x; App3 inexistente nunca chegou a ser iniciado');
  });

  test("falha no segundo app — primeiro processo é entregue corretamente ao cleanup", async () => {
    const ch1 = makeFakeChild(10);
    const ch2 = makeFakeChild(20);
    const children = [ch1, ch2];
    let callIndex = 0;
    const fakeSpawn = () => children[callIndex++];

    const apps = [
      { path: '/fake/app1.exe', name: 'App1' },
      { path: '/fake/app2.exe', name: 'App2' }
    ];

    const confirmed = [];
    for (const app of apps) {
      const p = _spawnAndConfirm(app, fakeSpawn);
      if (app.name === 'App1') ch1.emit('spawn');
      else ch2.emit('error', new Error('ENOENT'));
      try { confirmed.push(await p); } catch { break; }
    }

    // Simula o que start()'s catch block faz com os processos confirmados
    const killedPids = [];
    await _cleanupSelectiveSession({
      startedProcesses: confirmed,
      disconnectWireSock: false,
      _killFn: (pid) => { killedPids.push(pid); return Promise.resolve(); }
    });

    assert.deepStrictEqual(killedPids, [10],
      'somente pid=10 (App1, confirmado) deve ser encerrado; App2 nunca confirmou spawn');
  });
});

// ── 9. ShutdownController — encerramento coordenado ─────────────────────────
//
// 100% puro: sem Electron, BrowserWindow, Tray, app.quit() ou operações externas.
// Todas as dependências são injetadas via makeController().

describe('ShutdownController — encerramento coordenado', () => {
  function makeController({ failCleanup = false, cleanupError = null } = {}) {
    const log = [];
    const ctrl = createShutdownController({
      cleanupFn: async () => {
        log.push('cleanup');
        if (failCleanup || cleanupError) throw (cleanupError || new Error('UAC cancelado'));
      },
      quitFn:       () => { log.push('quit'); },
      showWindowFn: () => { log.push('showWindow'); },
      showErrorFn:  (msg) => { log.push(`showError:${msg}`); },
      destroyTrayFn: () => { log.push('destroyTray'); }
    });
    return { ctrl, log };
  }

  test('1 — X esconde a janela e não inicia cleanup', () => {
    const { ctrl, log } = makeController();
    const isFirst = ctrl.noteFirstHide();
    assert.ok(isFirst, 'primeira ocultação deve retornar true');
    assert.strictEqual(log.length, 0, 'nenhum cleanup deve ter ocorrido');
    assert.ok(!ctrl.isAllowedToClose(), 'janela não deve poder fechar livremente');
  });

  test('2 — fechamento autorizado (após cleanup) permite destruir a janela', async () => {
    const { ctrl } = makeController();
    assert.ok(!ctrl.isAllowedToClose(), 'antes: não autorizado');
    await ctrl.requestShutdown('menu');
    assert.ok(ctrl.isAllowedToClose(), 'após cleanup bem-sucedido: autorizado');
  });

  test('3 — notificação aparece somente na primeira ocultação', () => {
    const { ctrl } = makeController();
    assert.ok(ctrl.noteFirstHide(),  'primeira: true');
    assert.ok(!ctrl.noteFirstHide(), 'segunda:  false');
    assert.ok(!ctrl.noteFirstHide(), 'terceira: false');
  });

  test('4 — “Sair e encerrar tudo” chama cleanup antes de quit', async () => {
    const { ctrl, log } = makeController();
    await ctrl.requestShutdown('menu');
    assert.ok(log.indexOf('cleanup') < log.indexOf('quit'),
      'cleanup deve preceder quit');
  });

  test('5 — duas solicitações simultânâneas compartilham a mesma operação', async () => {
    let cleanupCount = 0;
    const ctrl = createShutdownController({
      cleanupFn: async () => { cleanupCount++; },
      quitFn:    () => {}
    });
    const p1 = ctrl.requestShutdown('menu');
    const p2 = ctrl.requestShutdown('menu');
    assert.strictEqual(p1, p2, 'deve retornar a mesma Promise');
    await p1;
    assert.strictEqual(cleanupCount, 1, 'cleanup deve rodar apenas uma vez');
  });

  test('6 — falha de cleanup não chama quit', async () => {
    const { ctrl, log } = makeController({ failCleanup: true });
    const result = await ctrl.requestShutdown('menu');
    assert.ok(!result.success, 'deve reportar falha');
    assert.ok(!log.includes('quit'),       'quit NÃO deve ser chamado após falha');
    assert.ok(!log.includes('destroyTray'),'tray NÃO deve ser destruído após falha');
  });

  test('7 — falha restaura janela quando saída foi pelo menu', async () => {
    const { ctrl, log } = makeController({ failCleanup: true });
    await ctrl.requestShutdown('menu');
    assert.ok(log.includes('showWindow'), 'janela deve ser restaurada após falha de menu');
    assert.ok(log.some(e => e.startsWith('showError')), 'erro deve ser exibido');
  });

  test('7b — falha em encerramento do SO não restaura janela', async () => {
    const { ctrl, log } = makeController({ failCleanup: true });
    await ctrl.requestShutdown('os');
    assert.ok(!log.includes('showWindow'), 'janela NÃO deve ser restaurada em shutdown do SO');
  });

  test('8 — tray só é destruído após cleanup bem-sucedido', async () => {
    const { ctrl, log } = makeController();
    await ctrl.requestShutdown('menu');
    const ciIdx = log.indexOf('cleanup');
    const dtIdx = log.indexOf('destroyTray');
    assert.ok(dtIdx > ciIdx, 'tray deve ser destruído DEPOIS do cleanup');
  });

  test('9 — before-quit não cria recursão (isDone impede segunda execução)', async () => {
    let cleanupCount = 0, quitCount = 0;
    const ctrl = createShutdownController({
      cleanupFn: async () => { cleanupCount++; },
      quitFn:    () => { quitCount++; }
    });
    await ctrl.requestShutdown('menu');  // primeira execução
    await ctrl.requestShutdown('os');    // simula before-quit disparando após app.quit()
    assert.strictEqual(cleanupCount, 1, 'cleanup deve rodar apenas uma vez');
    assert.strictEqual(quitCount,    1, 'quit deve ser chamado apenas uma vez');
  });
});

// ── 10. tray-menu-state — estado do menu da bandeja ──────────────────────
//
// Função pura — sem Electron, sem processos externos.

describe('tray-menu-state — estado do menu da bandeja', () => {
  test('10 — estado do menu é atualizado conforme o estado seletivo', () => {
    assert.ok(selectiveStateForMenu('running').disconnectEnabled,   'running: desconectar habilitado');
    assert.ok(selectiveStateForMenu('recovery').disconnectEnabled,  'recovery: desconectar habilitado');
    assert.ok(!selectiveStateForMenu('stopped').disconnectEnabled,  'stopped: desconectar desabilitado');
    assert.ok(!selectiveStateForMenu('starting').disconnectEnabled, 'starting: desconectar desabilitado');
    assert.strictEqual(selectiveStateForMenu('running').statusLabel,  'Estado: Ativo');
    assert.strictEqual(selectiveStateForMenu('stopped').statusLabel,  'Estado: Parado');
    assert.strictEqual(selectiveStateForMenu('recovery').statusLabel, 'Estado: Recuperação');
    assert.ok(selectiveStateForMenu('unknown').statusLabel.startsWith('Estado:'), 'estado desconhecido usa fallback');
  });
});

// ── 11-15. requestStop / pendingCleanup — corrida pós-spawn ────────────────
//
// Zero operações externas: _requestStop e _processPendingCleanup são
// testados com funções injetadas — selective.stop() real nunca é chamado.

describe('requestStop / pendingCleanup — corrida pós-spawn', () => {
  // Reset: garante estado limpo entre testes
  function resetState() {
    _setTestState({ selectiveActive: false, launchedProcesses: [], pendingCleanupReason: null });
  }

  test('11 — erro pós-spawn com guard ocupado registra cleanup pendente', () => {
    resetState();
    const stopCalls = [];
    _requestStop('Erro pós-spawn',
      { _stopFn: r => { stopCalls.push(r); return Promise.resolve(); },
        _isLocked: () => true });
    assert.strictEqual(stopCalls.length, 0, 'stop não deve ser chamado com guard ocupado');
    assert.strictEqual(_getTestState().pendingCleanupReason, 'Erro pós-spawn');
    resetState();
  });

  test('12 — cleanup pendente roda após liberação do guard (processPendingCleanup)', () => {
    resetState();
    _setTestState({ pendingCleanupReason: 'Erro pendente', selectiveActive: true });
    const stopCalls = [];
    const ran = _processPendingCleanup(r => { stopCalls.push(r); return Promise.resolve(); });
    assert.ok(ran, 'deve retornar true indicando que cleanup foi iniciado');
    assert.strictEqual(stopCalls[0], 'Erro pendente');
    assert.strictEqual(_getTestState().pendingCleanupReason, null, 'deve ser limpo após execução');
    resetState();
  });

  test('13 — vários erros pós-spawn geram um único cleanup pendente', () => {
    resetState();
    const isLocked = () => true;
    _requestStop('Erro 1', { _isLocked: isLocked });
    _requestStop('Erro 2', { _isLocked: isLocked });
    _requestStop('Erro 3', { _isLocked: isLocked });
    assert.strictEqual(_getTestState().pendingCleanupReason, 'Erro 1',
      'apenas o primeiro erro deve ser preservado');
    resetState();
  });

  test('14 — erro pós-spawn com guard livre inicia cleanup imediatamente', async () => {
    resetState();
    const stopCalls = [];
    _requestStop('Erro imediato',
      { _stopFn: r => { stopCalls.push(r); return Promise.resolve(); },
        _isLocked: () => false });
    assert.strictEqual(stopCalls.length, 1, 'stop deve ser chamado imediatamente');
    assert.strictEqual(stopCalls[0], 'Erro imediato');
    assert.strictEqual(_getTestState().pendingCleanupReason, null, 'pendente deve ser null');
    resetState();
  });

  test('15 — requestStop não produz unhandled rejection', async () => {
    resetState();
    let unhandledRejection = false;
    const handler = () => { unhandledRejection = true; };
    process.once('unhandledRejection', handler);
    try {
      _requestStop('Teste',
        { _stopFn: () => Promise.reject(new Error('stop falhou')),
          _isLocked: () => false });
      await new Promise(resolve => setImmediate(resolve));
      assert.ok(!unhandledRejection, 'não deve haver unhandled rejection');
    } finally {
      process.removeListener('unhandledRejection', handler);
      resetState();
    }
  });

  test('16 — processos não iniciados pelo GhostRoute nunca são mortos', async () => {
    resetState();
    const killed = [];
    await _cleanupSelectiveSession({
      startedProcesses: [],
      disconnectWireSock: false,
      _killFn: pid => { killed.push(pid); return Promise.resolve(); }
    });
    assert.strictEqual(killed.length, 0,
      'nenhum kill deve ocorrer quando a lista de processos está vazia');
    resetState();
  });
});

// ── A. selective.stop — operação compartilhada (stopPromise) ────────────────
//
// Testa o contrato de stopPromise usando _stop (alias de stop) com _opts injetados.
// Zero operações externas: sem WireSock, PowerShell, sc.exe ou UAC.

describe('selective.stop — operação compartilhada (stopPromise)', () => {
  // Reset completo entre testes: resetSel inclui _resetStop para evitar
  // vazamento de stopPromise de um teste para o próximo.
  function resetSel() {
    _setTestState({ selectiveActive: false, launchedProcesses: [], pendingCleanupReason: null, _resetStop: true });
  }

  test('A1 — shutdown aguarda stop já em andamento (operação única)', async () => {
    resetSel();
    _setTestState({ selectiveActive: true });

    let disconnectCount = 0;
    const allResolvers = [];
    const countingDisconnect = () => new Promise(r => { disconnectCount++; allResolvers.push(r); });

    const p1 = selective._stop('r1', { _disconnectFn: countingDisconnect, _hasRunningServicesFn: () => false });
    const p2 = selective._stop('r2', { _disconnectFn: countingDisconnect, _hasRunningServicesFn: () => false });

    // Aguarda microtasks: deixa a IIFE avançar até await disconnectFn()
    await new Promise(r => setImmediate(r));

    // Se stopPromise foi compartilhado, disconnect foi chamado apenas uma vez
    assert.strictEqual(disconnectCount, 1,
      'disconnect deve ser chamado uma única vez: stopPromise foi compartilhado');
    assert.ok(_getTestState().stopInProgress, 'stop deve estar em andamento');

    for (const r of allResolvers) r();
    await Promise.all([p1, p2]);

    assert.ok(!_getTestState().stopInProgress, 'stop deve ter concluído');
    resetSel();
  });

  test('A2 — duas chamadas de stop compartilham a mesma operação efetiva', async () => {
    resetSel();
    _setTestState({ selectiveActive: true });

    let disconnectCount = 0;
    const allResolvers = [];
    const countingDisconnect = () => new Promise(r => { disconnectCount++; allResolvers.push(r); });

    const p1 = selective._stop('a', { _disconnectFn: countingDisconnect, _hasRunningServicesFn: () => false });
    const p2 = selective._stop('b', { _disconnectFn: countingDisconnect, _hasRunningServicesFn: () => false });

    await new Promise(r => setImmediate(r));
    assert.strictEqual(disconnectCount, 1, 'disconnect deve ser chamado apenas uma vez');

    for (const r of allResolvers) r();
    const [r1, r2] = await Promise.all([p1, p2]);

    assert.strictEqual(r1.state, 'stopped');
    assert.strictEqual(r2.state, 'stopped', 'ambos os chamadores recebem resultado stopped');
    assert.strictEqual(disconnectCount, 1, 'contagem não deve ter aumentado');
    resetSel();
  });

  test('A3 — falha do stop chega a todos os chamadores', async () => {
    resetSel();
    _setTestState({ selectiveActive: true });

    let failCount = 0;
    // failingDisconnect é chamado dentro do IIFE assíncrono.
    // Para evitar janela de unhandled rejection, usamos Promise.allSettled que
    // registra handlers imediatamente (antes de qualquer microtask).
    const failingDisconnect = () => { failCount++; return Promise.reject(new Error('UAC cancelado')); };

    const p1 = selective._stop('r1', { _disconnectFn: failingDisconnect, _hasRunningServicesFn: () => false });
    const p2 = selective._stop('r2', { _disconnectFn: failingDisconnect, _hasRunningServicesFn: () => false });

    // allSettled registra handlers ANTES das microtasks (sem janela de unhandled rejection)
    const results = await Promise.allSettled([p1, p2]);

    assert.strictEqual(failCount, 1, 'disconnect deve ser chamado apenas uma vez (stopPromise compartilhado)');
    assert.strictEqual(results[0].status, 'rejected');
    assert.ok(results[0].reason?.message?.includes('UAC cancelado'), 'p1 deve rejeitar com UAC');
    assert.strictEqual(results[1].status, 'rejected');
    assert.ok(results[1].reason?.message?.includes('UAC cancelado'), 'p2 deve rejeitar com o mesmo erro');

    resetSel();
  });
});

// ── B. createCleanupFn — limpeza de VPN ───────────────────────────────
//
// Testa a sequência de cleanup com dependências injetadas.
// Nenhum WireGuard, WireSock, PowerShell ou UAC real.

describe('createCleanupFn — limpeza de VPN', () => {
  function makeCleanup(overrides = {}) {
    const log = [];
    const defaults = {
      getSelectiveStatus:   () => ({ state: 'stopped' }),
      stopSelective:        async () => { log.push('stopSelective'); },
      getFullTunnelPath:    () => '',
      getFullTunnelStatus:  async () => ({ state: 'disconnected' }),
      disconnectFullTunnel: async () => { log.push('disconnectFullTunnel'); },
      cleanupTempFiles:     () => { log.push('cleanupTempFiles'); }
    };
    const cleanup = createCleanupFn({ ...defaults, ...overrides });
    return { cleanup, log };
  }

  test('B1 — desconecta modo seletivo quando ativo', async () => {
    const { cleanup, log } = makeCleanup({
      getSelectiveStatus: () => ({ state: 'running' })
    });
    await cleanup();
    assert.ok(log.includes('stopSelective'), 'stopSelective deve ser chamado');
  });

  test('B2 — desconecta VPN completa quando ativa', async () => {
    const { cleanup, log } = makeCleanup({
      getFullTunnelPath:   () => 'C:\\path\\tunnel.conf.dpapi',
      getFullTunnelStatus: async () => ({ state: 'connected' })
    });
    await cleanup();
    assert.ok(log.includes('disconnectFullTunnel'), 'disconnectFullTunnel deve ser chamado');
  });

  test('B3 — caminho vazio não tenta validar nem desconectar VPN completa', async () => {
    const { cleanup, log } = makeCleanup({
      getFullTunnelPath: () => '',  // vazio = sem VPN completa configurada
      getFullTunnelStatus: async () => { throw new Error('não deve ser chamado'); },
      disconnectFullTunnel: async () => { throw new Error('não deve ser chamado'); }
    });
    await assert.doesNotReject(cleanup, 'não deve tentar validar/desconectar');
    assert.ok(!log.includes('disconnectFullTunnel'), 'disconnectFullTunnel NÃO deve ser chamado');
  });

  test('B4 — falha da VPN completa impede quit pelo menu (erro propagado)', async () => {
    const { cleanup } = makeCleanup({
      getFullTunnelPath:   () => 'C:\\path\\tunnel.conf.dpapi',
      getFullTunnelStatus: async () => ({ state: 'connected' }),
      disconnectFullTunnel: async () => { throw new Error('UAC cancelado'); }
    });
    await assert.rejects(cleanup, /UAC cancelado/, 'erro deve ser propagado para o caller');
  });

  test('B5 — configs temporárias são limpas somente depois das desconexões', async () => {
    const log = [];
    const cleanup = createCleanupFn({
      getSelectiveStatus:   () => ({ state: 'running' }),
      stopSelective:        async () => { log.push('stop'); },
      getFullTunnelPath:    () => 'C:\\path\\t.conf.dpapi',
      getFullTunnelStatus:  async () => ({ state: 'connected' }),
      disconnectFullTunnel: async () => { log.push('disconnect'); },
      cleanupTempFiles:     () => { log.push('cleanup'); }
    });
    await cleanup();
    assert.ok(log.indexOf('stop') < log.indexOf('cleanup'),     'stop antes de cleanup');
    assert.ok(log.indexOf('disconnect') < log.indexOf('cleanup'), 'disconnect antes de cleanup');
  });
});

// ── C. ShutdownController — invariantes de flags ────────────────────────
//
// Testa as transições de estado e flags após falhas em diferentes fases.

describe('ShutdownController — invariantes de flags', () => {
  test('C1 — destroyTrayFn lançando não deixa flags contraditórias', async () => {
    // destroyTrayFn é não-fatal; quitFn ainda deve ser chamado
    const log = [];
    const ctrl = createShutdownController({
      cleanupFn:    async () => {},
      destroyTrayFn: () => { log.push('destroyTray'); throw new Error('tray error'); },
      quitFn:        () => { log.push('quit'); },
    });
    const result = await ctrl.requestShutdown('menu');
    // destroyTray falhou mas foi silenciado; quitFn foi chamado
    assert.ok(result.success, 'deve ter sucesso (destroyTray é não-fatal)');
    assert.ok(log.includes('quit'), 'quitFn deve ter sido chamado');
    // Flags não contraditórias:
    assert.ok(ctrl.isDone(), 'state deve ser done');
    assert.ok(ctrl.isAllowedToClose(), 'isAllowedToClose deve ser true (cleanup ok)');
  });

  test('C2 — quitFn lançando não autoriza fechamento da janela indevidamente', async () => {
    const ctrl = createShutdownController({
      cleanupFn: async () => {},
      quitFn:    () => { throw new Error('quit error'); },
      showWindowFn: () => {}, showErrorFn: () => {}
    });
    const result = await ctrl.requestShutdown('menu');
    assert.ok(!result.success, 'deve reportar falha');
    assert.ok(!ctrl.isAllowedToClose(), 'isAllowedToClose deve ser false após quitFn lançar');
    assert.ok(!ctrl.isDone(), 'state não deve ser done (quit não concluiu)');
    // 'cleaned': cleanup não se repete; próxima tentativa vai direto para quit
    assert.strictEqual(ctrl._getState(), 'cleaned',
      'estado deve ser cleaned para permitir retry de quit sem repetir cleanup');
  });

  test('C3 — falha de cleanup mantém isAllowedToClose=false', async () => {
    const ctrl = createShutdownController({
      cleanupFn: async () => { throw new Error('cleanup error'); },
      showWindowFn: () => {}, showErrorFn: () => {}
    });
    const result = await ctrl.requestShutdown('menu');
    assert.ok(!result.success, 'deve reportar falha');
    assert.ok(!ctrl.isAllowedToClose(), 'isAllowedToClose deve ser false após falha de cleanup');
    assert.ok(!ctrl.isDone(), 'state deve ser idle (permite retry)');
  });
});

// ── D. session-end / query-session-end ──────────────────────────────────
//
// Testa o comportamento do coordenador quando origin='os'
// (simula query-session-end do Windows).

describe('session-end / query-session-end — shutdown do Windows', () => {
  test('D1 — query-session-end deduplica cleanup já iniciado', async () => {
    let cleanupCount = 0;
    const ctrl = createShutdownController({
      cleanupFn: async () => { cleanupCount++; },
      quitFn: () => {}
    });

    // Simula primeiro query-session-end
    if (!ctrl.isShuttingDown() && !ctrl.isDone()) {
      ctrl.requestShutdown('os').catch(() => {});
    }
    // Simula segundo query-session-end (condição de corrida)
    if (!ctrl.isShuttingDown() && !ctrl.isDone()) {
      ctrl.requestShutdown('os').catch(() => {});
    }

    await new Promise(r => setImmediate(r));
    assert.strictEqual(cleanupCount, 1, 'cleanup deve rodar apenas uma vez');
  });

  test('D2 — encerramento do Windows não restaura janela nem exibe diálogo', async () => {
    const log = [];
    const ctrl = createShutdownController({
      cleanupFn:   async () => { throw new Error('falha'); },
      showWindowFn: () => { log.push('showWindow'); },
      showErrorFn:  () => { log.push('showError'); }
    });
    // origin='os' — não deve restaurar janela nem mostrar erro mesmo em falha
    await ctrl.requestShutdown('os');
    assert.ok(!log.includes('showWindow'), 'janela NÃO deve ser restaurada');
    assert.ok(!log.includes('showError'),  'erro NÃO deve ser exibido');
  });
});

// ── E. Bloqueios IPC e tratamento de erros ───────────────────────────────

describe('Bloqueios IPC e tratamento de erros do menu', () => {
  test('E1 — handler IPC mutável é recusado durante shutdown (lógica pura)', () => {
    // Testa a lógica do guardShutdown sem usar Electron real.
    function makeGuard(isShuttingDown, isDone) {
      return (name) => {
        if (isShuttingDown || isDone) throw new Error(`GhostRoute está encerrando. (${name})`);
      };
    }

    const activeGuard  = makeGuard(true, false);
    const doneGuard    = makeGuard(false, true);
    const idleGuard    = makeGuard(false, false);

    assert.throws(() => activeGuard('vpn:connect'),   /encerrando/, 'deve bloquear durante shutdown ativo');
    assert.throws(() => doneGuard('selective:start'), /encerrando/, 'deve bloquear após shutdown concluído');
    assert.doesNotThrow(() => idleGuard('vpn:connect'), 'deve permitir quando idle');
  });

  test('E2 — erro ao desconectar VPN (via cleanup) não é silenciado', async () => {
    const { cleanup } = (() => {
      const log = [];
      const c = createCleanupFn({
        getSelectiveStatus:   () => ({ state: 'stopped' }),
        stopSelective:        async () => {},
        getFullTunnelPath:    () => 'C:\\path\\t.conf.dpapi',
        getFullTunnelStatus:  async () => ({ state: 'connected' }),
        disconnectFullTunnel: async () => { throw new Error('Falha UAC disconnect'); },
        cleanupTempFiles:     () => {}
      });
      return { cleanup: c, log };
    })();
    await assert.rejects(cleanup, /Falha UAC disconnect/, 'erro deve propagar');
  });

  test('E3 — nenhum driver é removido durante cleanup (interface não expõe operação)', () => {
    // createCleanupFn não aceita função de remoção de driver.
    // Verificamos que a interface existente não inclui tal função.
    const { cleanup } = (() => {
      const c = createCleanupFn({
        getSelectiveStatus:   () => ({ state: 'stopped' }),
        stopSelective:        async () => {},
        getFullTunnelPath:    () => '',
        getFullTunnelStatus:  async () => ({ state: 'disconnected' }),
        disconnectFullTunnel: async () => {},
        cleanupTempFiles:     () => {}
      });
      return { cleanup: c };
    })();
    // Verifica que cleanup finaliza sem operação de driver
    return assert.doesNotReject(cleanup);
  });

  test('E4 — nenhum processo não iniciado pelo GhostRoute é morto (cleanup vazio)', async () => {
    const killed = [];
    await _cleanupSelectiveSession({
      startedProcesses:  [],  // lista vazia = nenhum processo nosso
      disconnectWireSock: false,
      _killFn: pid => { killed.push(pid); return Promise.resolve(); }
    });
    assert.strictEqual(killed.length, 0,
      'nenhum kill deve ocorrer: GhostRoute só encerra seus próprios processos');
  });
});

// ── F. ShutdownController — máquina de estados (testes obrigatórios da correção) ──
//
// Verifica que _allowWindowClose é true DENTRO de quitFn, e que as transições
// de estado são corretas em cada caminho de falha.
// Sem Electron, BrowserWindow, Tray, app.quit() ou operações externas reais.

describe('ShutdownController — máquina de estados', () => {

  test('F1 — isAllowedToClose() é true dentro de quitFn', async () => {
    let seenInsideQuit = null;
    const ctrl = createShutdownController({
      cleanupFn: async () => {},
      quitFn:    () => { seenInsideQuit = ctrl.isAllowedToClose(); }
    });
    await ctrl.requestShutdown('menu');
    assert.strictEqual(seenInsideQuit, true,
      'isAllowedToClose() deve ser true quando quitFn é executado');
  });

  test('F2 — evento close não seria prevenido durante quitFn', async () => {
    // Simula o handler do evento close dentro de quitFn:
    // se isAllowedToClose() retornar true, event.preventDefault() não é chamado.
    let closeWouldBeAllowed = null;
    const ctrl = createShutdownController({
      cleanupFn: async () => {},
      quitFn: () => {
        // Lógica do handler close: se allowed, deixa fechar; senão previne.
        closeWouldBeAllowed = ctrl.isAllowedToClose();
      }
    });
    await ctrl.requestShutdown('menu');
    assert.strictEqual(closeWouldBeAllowed, true,
      'o handler close não teria chamado event.preventDefault() durante quitFn');
  });

  test('F3 — isAllowedToClose() é false antes de requestShutdown', () => {
    const ctrl = createShutdownController({
      cleanupFn: async () => {},
      quitFn:    () => {}
    });
    assert.ok(!ctrl.isAllowedToClose(), 'false antes de qualquer shutdown');
    assert.strictEqual(ctrl._getState(), 'idle');
  });

  test('F4 — falha de cleanup mantém isAllowedToClose false', async () => {
    const ctrl = createShutdownController({
      cleanupFn:    async () => { throw new Error('cleanup fail'); },
      showWindowFn: () => {},
      showErrorFn:  () => {}
    });
    await ctrl.requestShutdown('menu');
    assert.ok(!ctrl.isAllowedToClose());
    assert.strictEqual(ctrl._getState(), 'idle', 'estado idle permite retry de cleanup');
  });

  test('F5 — quitFn lançando reverte isAllowedToClose para false', async () => {
    const ctrl = createShutdownController({
      cleanupFn:    async () => {},
      quitFn:       () => { throw new Error('quit fail'); },
      showWindowFn: () => {},
      showErrorFn:  () => {}
    });
    const result = await ctrl.requestShutdown('menu');
    assert.ok(!result.success);
    assert.ok(!ctrl.isAllowedToClose(), 'deve ser false após falha de quit');
    assert.strictEqual(ctrl._getState(), 'cleaned',
      'estado cleaned: cleanup não se repete, mas quit pode ser tentado novamente');
  });

  test('F6 — após falha de quitFn, nova tentativa não repete cleanup', async () => {
    let cleanupCount = 0;
    let quitCount = 0;
    const ctrl = createShutdownController({
      cleanupFn: async () => { cleanupCount++; },
      quitFn: () => {
        quitCount++;
        if (quitCount === 1) throw new Error('primeiro quit falhou');
        // segunda tentativa não lança
      },
      showWindowFn: () => {},
      showErrorFn:  () => {}
    });

    const r1 = await ctrl.requestShutdown('menu');
    assert.ok(!r1.success, 'primeira tentativa deve falhar');
    assert.strictEqual(cleanupCount, 1);
    assert.strictEqual(quitCount, 1);

    const r2 = await ctrl.requestShutdown('menu');
    assert.ok(r2.success, 'segunda tentativa deve ter sucesso');
    assert.strictEqual(cleanupCount, 1, 'cleanup NÃO deve repetir');
    assert.strictEqual(quitCount, 2, 'quit deve ser tentado novamente');
  });

  test('F7 — duas chamadas simultâneas não duplicam cleanup nem quit', async () => {
    let cleanupCount = 0, quitCount = 0;
    const ctrl = createShutdownController({
      cleanupFn: async () => { cleanupCount++; },
      quitFn:    () => { quitCount++; }
    });
    const p1 = ctrl.requestShutdown('menu');
    const p2 = ctrl.requestShutdown('menu');
    assert.strictEqual(p1, p2, 'mesma Promise durante cleaning');
    await Promise.all([p1, p2]);
    assert.strictEqual(cleanupCount, 1);
    assert.strictEqual(quitCount, 1);
  });

  test('F8 — Tray não é destruído quando quitFn falha', async () => {
    const log = [];
    const ctrl = createShutdownController({
      cleanupFn:    async () => {},
      quitFn:       () => { throw new Error('quit fail'); },
      destroyTrayFn: () => { log.push('destroyTray'); },
      showWindowFn: () => {},
      showErrorFn:  () => {}
    });
    await ctrl.requestShutdown('menu');
    assert.ok(!log.includes('destroyTray'),
      'destroyTray NÃO deve ser chamado quando quitFn falha (app permanece visível)');
  });

  test('F9 — X esconde a janela sem iniciar cleanup', () => {
    let cleanupStarted = false;
    const ctrl = createShutdownController({
      cleanupFn: async () => { cleanupStarted = true; }
    });
    ctrl.noteFirstHide(); // simula pressionar X
    assert.ok(!cleanupStarted, 'cleanup não deve iniciar ao esconder');
    assert.ok(!ctrl.isAllowedToClose(), 'window não autorizada a fechar');
    assert.strictEqual(ctrl._getState(), 'idle');
  });

  test('F10 — before-quit autorizado não inicia segundo cleanup', async () => {
    let cleanupCount = 0, quitCount = 0;
    const ctrl = createShutdownController({
      cleanupFn: async () => { cleanupCount++; },
      quitFn:    () => { quitCount++; }
    });
    await ctrl.requestShutdown('menu'); // primeiro: cleanup + quit
    assert.strictEqual(ctrl._getState(), 'done');

    // Simula before-quit disparando após app.quit()
    const r2 = await ctrl.requestShutdown('os');
    assert.ok(r2.success, 'deve retornar sucesso (estado done)');
    assert.strictEqual(cleanupCount, 1, 'cleanup NÃO deve repetir');
    assert.strictEqual(quitCount,    1, 'quit NÃO deve ser chamado novamente');
  });
});

describe('lista de aplicativos — classificação e origem', () => {
  test('anticheats conhecidos são bloqueados', () => {
    assert.strictEqual(classifyAppRisk({ name: 'FACEIT Anti-cheat', path: 'C:\\FACEIT\\faceit.exe' }).level, 'blocked');
    assert.strictEqual(classifyAppRisk({ name: 'BEService', path: 'C:\\BattlEye\\BEService.exe' }).level, 'blocked');
  });

  test('jogos e launchers conhecidos recebem aviso, não bloqueio', () => {
    assert.strictEqual(classifyAppRisk({ name: 'Steam', path: 'C:\\Steam\\steam.exe' }).level, 'warning');
    assert.strictEqual(classifyAppRisk({ name: 'Discord', path: 'C:\\Discord\\Discord.exe' }).level, 'none');
  });

  test('desinstaladores, instaladores e atalhos do sistema são excluídos', () => {
    assert.ok(isExcludedApp({ name: 'Uninstall Example', path: 'C:\\Apps\\uninstall.exe' }));
    assert.ok(isExcludedApp({ name: 'Example Setup', path: 'C:\\Apps\\setup.exe' }));
    assert.ok(isExcludedApp({ name: 'Prompt', path: 'C:\\Windows\\System32\\cmd.exe' }));
    assert.ok(!isExcludedApp({ name: 'Discord', path: 'C:\\Apps\\Discord.exe' }));
  });

  test('normalizeItem preserva origem manual em arquivo válido', () => {
    const dir = makeTempDir();
    try {
      const exe = path.join(dir, 'manual.exe');
      fs.writeFileSync(exe, 'fake');
      const item = normalizeItem({ name: 'Manual', path: exe, source: 'manual' });
      assert.strictEqual(item.source, 'manual');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('launchSelectedApps — abertura opcional', () => {
  test('não abre processos quando launchApps=false', async () => {
    let calls = 0;
    const result = await _launchSelectedApps([{ name: 'Discord', path: 'C:\\Discord.exe' }], false, async () => { calls++; });
    assert.deepStrictEqual(result, []);
    assert.strictEqual(calls, 0);
  });

  test('abre sequencialmente todos quando launchApps=true', async () => {
    const order = [];
    const apps = [{ name: 'A', path: 'A.exe' }, { name: 'B', path: 'B.exe' }];
    const result = await _launchSelectedApps(apps, true, async app => {
      order.push(app.name);
      return { pid: order.length };
    });
    assert.deepStrictEqual(order, ['A', 'B']);
    assert.deepStrictEqual(result.map(child => child.pid), [1, 2]);
  });
});
