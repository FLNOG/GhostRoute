# GhostRoute — Contexto de continuidade

Atualizado em: 30 de outubro de 2026 (catálogo autoritativo, interface UWP/launchers, refatoração, correções críticas)

Este documento permite que outra IA ou desenvolvedor continue o projeto sem depender do histórico da conversa. Leia este arquivo e o `README.md` antes de alterar o código.

## Objetivo do produto

GhostRoute é um aplicativo Windows em Electron que encaminha somente os aplicativos escolhidos por uma VPN WireGuard. O restante do computador permanece na conexão normal.

O caso inicial é Discord, incluindo mensagens, voz, câmera e compartilhamento de tela. O produto será usado de forma pessoal e não comercial entre amigos.

Fluxo final desejado:

```text
Instalar → inserir convite → escolher aplicativos → conectar
```

O usuário final não deve precisar conhecer WireGuard, baixar `.conf`, escolher executáveis manualmente, informar IP interno ou manipular chaves.

## Diretório do projeto

```text
C:\Users\Suporte\Documents\ChatGPT\VPN - Discord\GhostRoute
```

## Tecnologias

- Electron 45, CommonJS.
- WireSock Secure Connect 3.8.1 para filtragem TCP/UDP por aplicativo.
- WireGuard oficial instalado no computador, incluindo `wg.exe` para geração de chaves.
- Windows DPAPI (`CurrentUser`) para proteger chaves privadas locais.
- Oracle Cloud VPS com Ubuntu e WireGuard.

## VPS de desenvolvimento

- IP público: `193.122.219.14`
- Porta WireGuard: `51820/UDP`
- Interface: `wg0`
- Rede VPN: `10.77.0.0/24`
- Chave pública do servidor: `KCZBfJDh4NlhY1O9yyBO9QqaTDN9zOq6Skky3wXMDVg=`

Peers conhecidos:

```text
QlUXnZvij795hjs0klGX6Lxs4K8zbp4na/C4wXxB1n4=  10.77.0.2/32  # identidade antiga de teste
3+koBTOnpJjnzaxIZVQbIyRLR30gjeNfUtIViP3mv1o=  10.77.0.3/32  # SUPORTEFELIPE
```

O peer `SUPORTEFELIPE` foi persistido em `/etc/wireguard/wg0.conf` e aplicado em runtime com `wg set`.

Nunca adicionar chaves privadas, arquivos `.conf` reais ou credenciais SSH a este documento ou ao Git.

## Estado validado

### Roteamento seletivo

- Discord funciona pelo IP da VPS.
- Mensagens, voz, câmera e compartilhamento/visualização de tela foram testados.
- Dois aplicativos selecionados simultaneamente funcionaram.
- Aplicativo não selecionado permaneceu na conexão normal.
- Três ciclos consecutivos de conexão, handshake e desconexão foram validados.
- O WireSock recebe `AllowedApps` gerado pelo GhostRoute.
- DNS foi removido do perfil seletivo porque o WireSock o aplicaria globalmente no Windows.

### Lista de aplicativos

- Descoberta automática de atalhos no Menu Iniciar.
- Busca, ícones, seleção múltipla e persistência.
- Inclusão manual de `.exe` como contingência.
- Discord acompanha automaticamente a versão mais recente em `%LOCALAPPDATA%\Discord\app-*\Discord.exe`.
- Aplicativos selecionados precisam estar fechados antes de iniciar; o GhostRoute os abre depois da conexão.

### WireSock

- Cliente completo instalado pelo pacote Winget `NTKERNEL.WireSockVPNClient`.
- Não usar `sdk\wiresock-client.exe` quando o cliente completo está instalado: ele falha tentando acessar diretamente o driver já mantido pelos serviços.
- Usar:

```text
C:\Program Files\WireSock Secure Connect\command-line\wiresock-connect-cli.exe
```

- Perfil controlado: `wiresock.generated`.
- A CLI retorna código `2` em situações não fatais:
  - perfil já existente durante `import`;
  - desconexão concluída.
- O controlador remove o perfil anterior, importa o novo, conecta e aguarda a confirmação da CLI.

### Ciclo de vida dos serviços

Serviços:

```text
WireSockAppService
WireSockConnectService
```

- Ambos foram configurados como inicialização manual.
- São iniciados ao conectar pelo GhostRoute.
- São parados ao encerrar o modo seletivo.
- A internet continua funcionando quando somente esses serviços são parados.

Driver:

```text
ndiswgc.sys
Serviço: ndiswgc
Componente NDIS: nt_ndiswgc
```

- O driver é assinado por `Microsoft Windows Hardware Compatibility Publisher`.
- Test Signing e Kernel Debugging estavam desativados.
- Parar/descarregar `ndiswgc` derrubou a internet durante o teste.
- Portanto, o GhostRoute não deve descarregar automaticamente esse driver.
- O driver permanece instalado e carregado mesmo com os processos WireSock parados.

### Identidade por dispositivo

- A seção **Identidade do dispositivo** gera chave privada/publica com `wg.exe`.
- A chave privada é protegida via DPAPI e salva como `privateKeyDpapi`.
- A resposta IPC e a interface nunca recebem a chave privada.
- A identidade real atual:

```text
Dispositivo: SUPORTEFELIPE
ID: 4cc309cd-b5d4-4477-b7ee-471efd0213a7
Chave pública: 3+koBTOnpJjnzaxIZVQbIyRLR30gjeNfUtIViP3mv1o=
Endereço: 10.77.0.3/32
Status: active
```

- A nova identidade foi ativada e testada com sucesso.
- O perfil em texto puro é materializado somente durante a importação no WireSock e removido em seguida.
- A identidade antiga `10.77.0.2/32` ainda não foi revogada; mantê-la até uma decisão explícita do usuário.

## Anticheats

Não prometer compatibilidade nem ausência de banimento.

- GhostRoute não injeta DLL, não lê memória de jogos e não altera executáveis.
- FACEIT pode bloquear drivers incompatíveis ou vulneráveis.
- BattlEye normalmente diferencia bloqueio/kick de banimento, mas não há aprovação específica para WireSock.
- VAC não publicou aprovação específica para WireSock.
- Fechar GhostRoute e parar serviços não torna `ndiswgc` invisível, pois o driver continua instalado/carregado.
- Testes com anticheat devem ocorrer em outro computador e sem contas valiosas.
- Não selecionar jogos competitivos em `AllowedApps` durante validações.

## Segurança e arquivos sensíveis

O `.gitignore` cobre:

```text
wireguard/
*.conf
*.conf.dpapi
node_modules/
```

Arquivos sensíveis atualmente podem existir em:

```text
GhostRoute\wireguard\ghostroute-teste.conf
GhostRoute\wireguard\wiresock.generated.conf  # deve ser transitório/removido após uso
%APPDATA%\ghostroute\device-identity.json     # chave privada apenas em DPAPI
```

Não imprimir conteúdo desses arquivos em logs ou respostas.

## Arquivos principais

```text
src/main.js                         IPC, configurações, janela e orquestração
src/preload.js                      API segura renderer ↔ main
src/renderer.js                     interface e estados
src/index.html                      estrutura visual
src/styles.css                      estilos
src/vpn/selective-controller.js     WireSock, AllowedApps, serviços e processos
src/vpn/installed-apps.js           descoberta de aplicativos desktop
src/vpn/identity-manager.js         chaves, DPAPI e perfil temporário
src/vpn/wireguard-controller.js      modo VPN completa legado
src/vpn/network-diagnostics.js      DNS, IPv4 e IPv6
src/vpn/operation-guard.js          trava de concorrência pura (sem I/O)
src/vpn/app-model.js                modelo canônico de app (routeRule, migração, launcher, risco)
src/vpn/uwp-discovery.js            descoberta de apps Microsoft Store/UWP
src/catalog-utils.js                lógica pura de catálogo (testável sem Electron)
src/shutdown-controller.js          coordenador idêmpotente de encerramento
src/app-cleanup.js                  fábrica da função de cleanup com injetáveis
src/tray-menu-state.js              lógica pura de estado do menu da bandeja
src/assets/ghostroute-ghost.png      símbolo oficial; ícone da janela, hero e bandeja
src/assets/ghostroute-wordmark.png   logotipo horizontal usado no cabeçalho
src/tests/ghost-route.test.js       testes automatizados (147 casos, Node 18+)
```

## Comandos de desenvolvimento

```powershell
cd "C:\Users\Suporte\Documents\ChatGPT\VPN - Discord\GhostRoute"
npm run check
npm test
npm audit --omit=dev
npm start
```

Antes de entregar alterações, executar `npm run check`, `npm test` e `npm audit --omit=dev`.

## Decisões importantes

1. Não incorporar uma única chave privada no código para todos os amigos. WireGuard alternaria o endpoint do mesmo peer e as conexões disputariam entre si.
2. Cada dispositivo deve ter chave e IP próprios.
3. A chave privada nunca sai do computador.
4. Dados públicos da VPS podem estar no código.
5. O usuário final não deve informar o IP interno; o campo atual é temporário.
6. O WireSock deve ser baixado da fonte oficial, preferencialmente via Winget, e não simplesmente redistribuído dentro do instalador sem verificar licença.
7. O driver não deve ser descarregado automaticamente porque isso interrompeu a rede.

## Fluxo final de convites

Objetivo:

1. Administrador gera convite de uso único.
2. Amigo instala GhostRoute.
3. Amigo digita somente algo como `GHOST-7KQ2-MP9X`.
4. GhostRoute gera a chave privada localmente.
5. Envia convite, ID e chave pública para uma API na VPS.
6. API valida/invalida o convite, escolhe o próximo IP livre e cadastra o peer.
7. API retorna somente IP interno e dados públicos do servidor.
8. GhostRoute ativa a identidade e mostra a lista de aplicativos.

O usuário não deve ver chave, IP interno ou `.conf`.

## Roadmap acordado

### Concluído

1. Estabilizar conexão com um e vários aplicativos.
2. Melhorar recuperação de perfil residual e atualizações do Discord.
3. Controlar processos/serviços WireSock com segurança.
4. Gerar identidade individual e ativar manualmente um peer.

### Próximas etapas

1. Substituir o campo de IP por **Código de convite**.
2. Criar API mínima na VPS para convites, alocação de IP e cadastro/revogação de peers.
3. Criar armazenamento administrativo de dispositivos e IPs, evitando colisões.
4. Adicionar confirmação de handshake/diagnóstico específico do modo seletivo na interface.
5. Melhorar lista de aplicativos:
   - separar selecionados/instalados;
   - remover itens manuais;
   - tratar launchers e Microsoft Store;
   - opção de não abrir automaticamente.
6. Testar em segundo computador.
7. Investigar anticheats com fornecedores e máquina de teste.
8. Criar instalador `GhostRoute-Setup.exe`:
   - Electron/Node incluídos;
   - instalar WireSock oficialmente via Winget;
   - atalhos/desinstalador;
   - UAC e reinicialização pendente;
   - nunca incluir credenciais.
9. Distribuir primeiro para um único amigo e validar.

## Próximo passo exato recomendado

Projetar e implementar a API mínima de convites na VPS. Antes de alterar a VPS, definir:

- linguagem/serviço da API;
- autenticação administrativa;
- formato e expiração dos convites;
- armazenamento de peers/IPs;
- endpoint de ativação;
- como aplicar alterações ao `wg0` com privilégio mínimo;
- firewall, TLS, rate limiting e logs sem segredos.

Não expor diretamente comandos WireGuard ou acesso SSH pela API pública.

## Histórico de alterações significativas

### Sessão de revisão e testes — 30 out 2026

Uma auditoria técnica identificou os problemas abaixo. Uma IA intermediaria aplicou correções parciais; esta sessão revisou, corrigiu regressaões e adicionou testes.

**Correções aplicadas:**

1. `wiresock.generated.conf` movido de `wireguard/` (dentro do projeto, passível de sync OneDrive) para `%APPDATA%\ghostroute\` via parâmetro `runtimeDirectory`.
2. Limpeza de arquivos residuais (`ghostroute-session-*.conf` e `wiresock.generated.conf`) adicionada na inicialização do app via `identityManager.cleanupStaleConfigs()`.
3. `operationInProgress` adicionado ao `selective-controller` como guard contra chamada dupla a `start()` e `stop()`.
4. Estado `recovery` adicionado: detectado via `spawnSync sc.exe query` quando serviços WireSock estão ativos mas o GhostRoute não os iniciou (crash anterior).
5. Check de vírgula em `normalizeApps` movido para ANTES de `validateFile` — garante mensagem correta mesmo sem o arquivo existir e permite testes sem arquivos reais.
6. `renderer.js`: `setSelectiveState(status.state)` corrigido para `setSelectiveState(status.state, status.message)` — mensagem de recuperação agora exibida na inicialização.
7. CSP reforçada via `session.defaultSession.webRequest.onHeadersReceived` no processo principal (`object-src 'none'`, `base-uri 'self'`, `form-action 'none'`, `frame-ancestors 'none'`).
8. `isExecutableRunning` migrado de `tasklist.exe` para PowerShell com filtro por caminho completo (`Get-Process | Where-Object { $_.Path -ieq $target }`).
9. Argumento PowerShell em `runElevatedWireSock` corrigido de `.join(', ')` para `.join(' ')` (argumentos separados por espaço, não vírgula).
10. `windowsDnsServers()` em `network-diagnostics.js` convertido para `-EncodedCommand`.
11. Código morto em `resolveDiscordExecutable` removido (`basename === 'update.exe' ? parent : parent`).
12. `allowScripts` removido do `package.json` (campo não reconhecido pelo npm).
13. `SERVER_IP` renomeado de `EXPECTED_EXIT_IP`; o resultado de `start()` agora retorna `serverIp` em vez de `exitIp`.

**Testes automatizados criados** (`src/tests/ghost-route.test.js`, 24 testes, 0 falhas, ~126 ms):
- `publicIdentity` nunca expõe `privateKeyDpapi`
- `cleanupStaleConfigs` remove somente arquivos autorizados
- `removeMaterializedConfig` não deleta caminhos arbitrários
- Caminhos com vírgula são rejeitados antes de `fs.existsSync` (via `selective.prepare`)
- Lista vazia de apps é rejeitada (via `selective.prepare`, sem operação externa)
- `buildWireSockConfig` gera `AllowedApps` correto, remove DNS, usa CRLF
- Arquivo gerado é removível por `fs.rmSync`
- `OperationGuard` (7 testes): propriedade de token, idempotência, instâncias isoladas
- Release stale não desbloqueia aquisição posterior (invariante crítica)
- `cleanupSelectiveSession` (6 testes): kill parcial, disconnect condicional,
  resiliência a falhas de kill/notify, verificação de estado via `_getTestState`
- `spawnAndConfirm` (8 testes, via `_spawnAndConfirm` + EventEmitter fake):
  listener ativo antes de 'spawn', substituição temporário→permanente,
  rejeição por 'error' pré-spawn, somente confirmados na lista, integração com cleanup

**Isolamento e arquitetura dos testes:**
- `src/vpn/operation-guard.js`: módulo puro extraído para a trava de concorrência.
  Usa token `Symbol()` por aquisição — release stale é silenciosamente ignorada.
- `selective.start()` **não é chamado em nenhum teste**.
- Nenhum teste alcança PowerShell, sc.exe, WireSock CLI, UAC ou spawn de processo.
- `start()` foi simplificado: catch removido (era dead code), cleanup de config
  movido para `finally`, `releaseOperation()` chamada exatamente uma vez.
- **Correção de falha pós-commit**: `start()` reescrito com spawn sequencial, `cleanupSelectiveSession`
  interna, proteção de `onStatusChange` e tratamento de processos parcialmente iniciados.
- `cleanupSelectiveSession` com dependências injetáveis (`_killFn`, `_disconnectFn`, `_notifyFn`).
- `onStatusChange` protegido em `start()` e `stop()` com `try { ... } catch {}` — falha de notificação não-fatal.
- Listeners de erro em processos usam `.catch(() => {})` para suprimir rejeições não tratadas.
- `spawnAndConfirm`: helper que registra o listener de `'error'` **imediatamente** após
  `spawn()` retornar, aguarda `'spawn'` para confirmar início, rejeita em `'error'` pré-spawn
  e substitui o listener temporário por um permanente após confirmação. Somente processos
  confirmados são inseridos em `startedProcesses`.
- `cleanupSelectiveSession`: `Promise.all` usa wrapper `async/await` para normalizar
  tanto lançamentos síncronos quanto rejeições de Promise do `_killFn`.
- **Bandeja do sistema** (`src/main.js`): `Tray` + `Menu` + ícone PNG gerado em runtime.
  X na janela esconde (não destrói); notificação somente na primeira vez.
- **ShutdownController** (`src/shutdown-controller.js`): coordenador idêmpotente.
  - “Sair e encerrar tudo”: cleanup → destroyTray → app.quit().
  - Falha (UAC cancelado): restaura janela, exibe erro, permite nova tentativa.
  - before-quit do SO: melhor esforço + `app.exit(0)` como último recurso documentado.
- **Corrida pós-spawn** corrigida: `requestStop` + `_processPendingCleanup` garantem
  que erros pós-spawn durante `start()` são executados após a liberação do guard.
- **Testes**: 55 testes, 0 falhas, ~156 ms.

**Riscos ainda pendentes (ver relatório de auditoria):**
- Validação de endereço em `activate()` hardcoded para `10.77.0.0/24` — bloqueador para produção.
- `api.ipify.org` como serviço externo de verificação de IP — substituir por endpoint na própria VPS.
- `mode: 0o600` tem efeito limitado no Windows — NTFS ACL domina.
- Sem helper privilegiado dedicado; toda elevação passa pelo processo Electron inteiro.

## Auditoria externa e correções aplicadas

Uma auditoria estática externa foi recebida em 30 de outubro de 2026. Foram corrigidos imediatamente:

- limpeza, na inicialização, de `ghostroute-session-*.conf` e `wiresock.generated.conf` residuais;
- geração do perfil transitório em `%APPDATA%\ghostroute`, não mais em `Documents`;
- trava no controlador contra duas inicializações simultâneas;
- rejeição clara de aplicativos cujo caminho contém vírgula;
- detecção de processo pelo caminho completo, não apenas pelo nome;
- argumentos PowerShell separados de forma explícita;
- CSP reforçada no processo principal e no HTML;
- detecção de serviços residuais após encerramento anormal;
- remoção da apresentação do IP fixo como se fosse uma medição real;
- PowerShell de diagnóstico DNS convertido para `-EncodedCommand`;
- remoção de código morto e do campo `allowScripts` não utilizado pelo npm.

Pendências conscientes da auditoria:

- estado real do túnel ainda não é consultado sem elevação; serviços residuais são mostrados como **Recuperação**, não como conexão confirmada;
- subnet e servidor continuam fixos enquanto a API de convites não existe;
- substituir `api.ipify.org` por endpoint próprio;
- endurecer ACL NTFS explicitamente;
- extrair utilitários PowerShell duplicados;
- planejar helper privilegiado e assinatura do instalador.

## Revisão corretiva de bandeja e shutdown — 30 out 2026

Correcões aplicadas após revisão detalhada:

1. `cleanupFn` do ShutdownController agora cobre **modo seletivo E VPN completa**, nessa ordem.
2. `selective.stop()` usa `stopPromise` (função regular, não async) para deduplicar chamadas concorrentes.
3. `before-quit` complementado por `query-session-end` e `session-end` para shutdown/logoff do Windows.
4. ShutdownController: `_allowWindowClose=true` só após `quitFn()` suceder; falha de `destroyTrayFn` é não-fatal.
5. Limpeza de configs temporárias via `cleanupTempFiles` é última etapa do cleanup.
6. Handlers IPC mutáveis (`vpn:connect/disconnect`, `identity:generate/activate`, `apps:save-selection`, `selective:start/stop`) bloqueados durante shutdown.

## Lista de aplicativos — primeira etapa de usabilidade

- A interface separa aplicativos **Selecionados** dos demais **Instalados**.
- Uma consulta única a `Win32_Process` marca executáveis atualmente abertos; o botão
  "Atualizar" refaz a descoberta e o estado dos processos.
- Itens adicionados manualmente preservam `source: "manual"` na configuração e podem
  ser removidos da lista.
- Instaladores, desinstaladores, atualizadores e atalhos administrativos do Windows são
  filtrados de forma conservadora.
- Anticheats conhecidos são bloqueados na seleção. Jogos e launchers conhecidos exibem
  alerta; a lista é apenas uma proteção auxiliar.
- A opção "Abrir aplicativos automaticamente" pode ser desativada.
- **Segunda etapa — modelo canônico de app** (`src/vpn/app-model.js`):
  - `routeRule` = regra para AllowedApps (nunca AUMID, nunca args, nunca processo compartilhado).
  - `launchTarget` = como abrir (exe para desktop, AUMID para UWP).
  - `launchArgs` = argumentos de abertura (nunca entram em AllowedApps).
  - Processos compartilhados bloqueados: ApplicationFrameHost, RuntimeBroker, explorer,
    WWAHost, ShellExperienceHost, msedgewebview2, e outros (ver SHARED_PROCESS_NAMES).
  - Launchers detectados automaticamente: Steam, Epic, Riot, Battle.net, Ubisoft, EA, GOG.
  - Configurações antigas `{ name, path }` migradas automaticamente por `migrateOldItem`.
- **Descoberta UWP** (`src/vpn/uwp-discovery.js`):
  - Usa `Get-AppxPackage` + `Get-AppxPackageManifest` via PowerShell.
  - `compatibility: supported` = caminho acessível; `experimental` = só basename; `unsupported` = processo compartilhado.
  - AUMID usado **somente** como `launchTarget` (lançamento via `shell:AppsFolder\\AUMID`).
  - Processos UWP não são rastreados em `launchedProcesses` (não são mortos ao desconectar).
  - **Limitação**: WireSock não documenta suporte a AUMID em AllowedApps; UWP experimental pode não rotear corretamente.
- Argumentos de atalhos preservados como array (nunca entram em AllowedApps);
  argumentos ambíguos (operadores shell, `$`) desativam abertura automática.
7. Menu “Desconectar VPN”: evita cliques concorrentes, exibe erro sem silenciá-lo.
8. `src/app-cleanup.js`: fábrica `createCleanupFn()` com dependências injetáveis para testes.
9. **Correção crítica**: ShutdownController reescrito com máquina de 5 estados (`idle`→`cleaning`→`cleaned`→`quitting`→`done`).
   - `_allowWindowClose=true` definido ANTES de `quitFn()` para que `app.quit()` não bloqueie o próprio encerramento.
   - Se `quitFn` lançar: `state→cleaned`, Tray preservado, cleanup não se repete.
   - `destroyTrayFn` chamado APÓS `quitFn` (evita app invisvel e sem menu em falha).
10. **Testes**: 82 casos, 0 falhas, ~145 ms (grupos A–F; grupo F é a máquina de estados).

## Provisionamento automático — API planejada

O fluxo atual ainda exige que o administrador cadastre a chave pública na VPS e que o
usuário informe manualmente o endereço interno atribuído, por exemplo `10.77.0.4/32`.
Isso é aceitável durante desenvolvimento, mas não será o fluxo do instalador definitivo.

### Experiência desejada

1. O administrador cria um convite de uso único e com validade.
2. O usuário instala o GhostRoute e informa apenas o código/link de convite.
3. O cliente gera a chave privada localmente e a protege com DPAPI.
4. Somente a chave pública, ID e nome do dispositivo são enviados à API.
5. A API valida e consome o convite, reserva atomicamente o próximo endereço livre,
   cadastra o peer no WireGuard e devolve os parâmetros públicos necessários.
6. O GhostRoute ativa a identidade automaticamente. A chave privada nunca sai do PC.

### Primeira arquitetura proposta

- API pequena em Node.js na VPS Oracle, executada como serviço dedicado.
- SQLite para convites, dispositivos, endereços reservados, revogações e auditoria.
- HTTPS obrigatório.
- Convites inicialmente de uso único e um dispositivo por convite.
- API pública mínima para enrollment e informações públicas da rede.
- Administração inicialmente por CLI local/SSH, sem painel web exposto: criar convite,
  listar dispositivos, revogar dispositivo e consultar endereços livres.
- Endpoint próprio de IP público para substituir `api.ipify.org`.
- A subnet e os dados públicos da rede devem vir do servidor, removendo o
  `10.77.0.0/24` fixo do cliente.

### Requisitos de segurança

- Nunca receber, armazenar ou registrar chaves privadas.
- Convites armazenados como hash, com expiração, consumo atômico e proteção contra replay.
- Alocação de endereço e cadastro do peer sob transação/lock para impedir IP duplicado.
- Validação estrita de chaves públicas, IDs e nomes; limites de tamanho e rate limiting.
- Integração com `wg` por helper/argumentos estruturados, sem concatenar shell input.
- Privilégio mínimo: processo HTTP sem root e componente privilegiado restrito para peers.
- Logs sem segredos, backups do banco e revogação idempotente.
- Endpoints administrativos não devem ficar publicamente expostos sem autenticação forte.

### Endpoints conceituais

- `POST /v1/enroll` — consome convite e cadastra a chave pública do dispositivo.
- `GET /v1/network-info` — devolve parâmetros públicos e versão do protocolo.
- `GET /v1/ip` — devolve o IP público observado pelo servidor.
- Convites e dispositivos ficam inicialmente na CLI administrativa, não na API pública.

### Ordem de implementação

1. Concluir e estabilizar a lista de aplicativos/UWP.
2. Definir protocolo, ameaças, estados e esquema SQLite.
3. Implementar API localmente com executor WireGuard simulado.
4. Testar concorrência, convites, reinstalação, idempotência e revogação.
5. Instalar a API na VPS com HTTPS e serviço supervisionado.
6. Integrar enrollment automático ao GhostRoute.
7. Ocultar a ativação manual em uma área avançada/de recuperação.
8. Somente depois produzir o instalador definitivo para os amigos.

## IP dinâmico, NAT e CGNAT dos clientes

- O computador do amigo **não precisa ter IP público fixo**. O WireGuard identifica o peer
  pela chave e aprende o endpoint externo mais recente a partir de pacotes autenticados
  (roaming entre IPs e redes).
- O endereço `10.77.0.x/32` é interno e estável no túnel; não é o IP público da internet.
- Como o cliente inicia UDP de saída para a VPS, normalmente não é necessário encaminhar
  portas no roteador do amigo, inclusive em redes com NAT/CGNAT.
- Trocar de Wi-Fi, reiniciar o modem ou receber outro IP público normalmente só exige novo
  handshake; o peer não precisa ser recadastrado.
- Para NAT/firewall que expira o mapeamento UDP, pode-se usar `PersistentKeepalive = 25`,
  conforme orientação prática do WireGuard quando é necessário manter o mapeamento ativo.
- Redes que bloqueiam UDP, portais cativos ou firewalls corporativos ainda podem impedir a
  conexão. O diagnóstico deve informar isso sem prometer funcionamento em toda rede.

## Arquitetura preferida do instalador final — componentes incorporados

Decisão de produto: para a versão final, a preferência é que o usuário instale e enxergue
apenas o **GhostRoute**, sem precisar operar interfaces separadas do WireGuard ou WireSock.
Isso corresponde à integração por SDK/serviço, e não a esconder ou renomear instalações de
terceiros.

### Arquitetura-alvo

```text
GhostRoute
├── Interface Electron sem privilégios administrativos permanentes
├── Serviço/helper GhostRoute privilegiado e de escopo mínimo
├── mecanismo seletivo WireSock SDK / wgbooster
├── componente WireGuard incorporável, se ainda necessário
└── drivers e serviços de rede assinados exigidos pelos mecanismos
```

Objetivos:

- um único instalador e uma única experiência de produto;
- apenas a interface do GhostRoute para conectar, desconectar, reparar e atualizar;
- drivers/serviços instalados com consentimento e UAC, mas sem exigir que o usuário abra
  aplicativos WireGuard ou WireSock separados;
- atualizações, diagnóstico e recuperação coordenados pelo GhostRoute;
- processo Electron comum sem privilégio; operações sensíveis ficam em helper restrito;
- preservar a capacidade de desligar VPN, serviços e processos iniciados pelo GhostRoute;
- não descarregar drivers de forma insegura durante uso normal;
- assinatura de código, verificação de integridade e rollback no instalador.

### WireGuard

O projeto oficial oferece `embeddable-dll-service` para aplicações Windows e recomenda essa
abordagem em vez de integrar WireGuardNT diretamente. Deve-se avaliar se o SDK WireSock já
cobre todos os modos necessários; se cobrir, o aplicativo oficial do WireGuard poderá deixar
de ser uma dependência de runtime. Geração de chaves também poderá ser interna, sem executar
`wg.exe`, desde que use implementação auditada e armazenamento DPAPI existente.

### WireSock

O WireSock Core SDK expõe o mecanismo `wgbooster`, drivers e APIs de ciclo de vida para uma
interface própria. Essa é a integração desejada para roteamento seletivo. Antes de embutir ou
redistribuir qualquer componente, é obrigatório obter confirmação escrita sobre:

- direito de redistribuição não comercial entre amigos;
- condições para uma futura distribuição pública/comercial;
- uso de drivers, DLLs, CLI/service wrapper e atualizações;
- marca, avisos de licença, telemetria e quantidade de dispositivos;
- necessidade de contrato OEM/Pro e respectivos custos.

Os termos publicados atualmente indicam que produção/redistribuição OEM comercial requer
acordo próprio. Não presumir autorização com base apenas no download gratuito.

### Estratégia de transição

1. Durante desenvolvimento, manter WireGuard/WireSock instalados separadamente e detectados
   pelo GhostRoute.
2. Criar uma abstração de engine para que controllers não dependam diretamente de caminhos
   fixos de executáveis.
3. Consultar formalmente o WireSock sobre licença de redistribuição/SDK.
4. Construir protótipo não distribuído com SDK e helper privilegiado.
5. Validar instalação, atualização, reparo, rollback e desinstalação em máquina limpa.
6. Migrar geração de chaves e túnel completo para componentes incorporados quando seguro.
7. Remover dependências separadas somente depois de equivalência funcional e licença válida.

## Rodada corretiva final — 30 out 2026

Correções aplicadas nesta sessão:

1. **`apps:remove-manual` (`src/main.js`)** — handler retornava `true` em ambos os casos e deletava do `appCatalog` mesmo para itens não-manuais. Corrigido:
   - Item não-manual: retorna `{ removed: false }` sem modificar config nem catálogo.
   - Item manual: salva config antes de remover do catálogo; retorna `{ removed: true }`.

2. **Botão "Remover" (`src/renderer.js`)** — não verificava `result.removed` antes de atualizar a UI. Corrigido para checar `result && result.removed === true`.

3. **Botão "Remover da seleção" (`src/renderer.js`)** — mutava `selectedIds` antes de persistir (sem rollback real). Substituído por `GhostRouteCatalog.removeFromSelectionWithRollback()` de `catalog-shared.js`, que:
   - Nunca muta o Set original.
   - Persiste primeiro, depois aplica a remoção.
   - Em falha retorna `{ committed: false, ids: prevSet, error }` e a UI restaura o estado.

4. **`package.json`** — adicionado `node --check src/catalog-shared.js` ao script `check`.

5. **Testes K1, K3, J9 (`src/tests/ghost-route.test.js`)** — estavam validando arquitetura obsoleta (contextBridge para `canonicalId` e `appMatchesFilter`). Corrigidos para refletir a arquitetura real:
   - K1: verifica que `preload.js` NÃO contém `require` local (sandbox:true).
   - K3: verifica que `renderer.js` usa `GhostRouteCatalog.canonicalId` (script tag).
   - J9: verifica que `renderer.js` usa `GhostRouteCatalog.appMatchesFilter` (script tag).

6. **Teste K8 (`src/tests/ghost-route.test.js`)** — reimplementava a lógica de rollback dentro do teste. Reescrito para usar a função real `removeFromSelectionWithRollback` de `catalog-shared.js`.

**Resultado:** 200 testes passando, 0 falhas, 0 vulnerabilidades (npm audit), `npm run check` OK.

### Arquitetura de compartilhamento de funções puras (resumo)

| Local | Forma de acesso |
|---|---|
| `src/catalog-shared.js` | Módulo UMD: em Node → `module.exports`; no browser → `globalThis.GhostRouteCatalog` |
| `src/catalog-utils.js` | `require('./catalog-shared')` + lógica adicional Node |
| `src/renderer.js` | `GhostRouteCatalog.*` (carregado via `<script src="catalog-shared.js">`) |
| `src/preload.js` | Somente `require('electron')` — sandbox:true impede require local |
| Testes | `require('../catalog-shared')` ou `require('../catalog-utils')` |

### Funções exportadas por catalog-shared.js

- `isValidId(id)` — valida string de ID
- `canonicalId(item)` — ID canônico normalizado
- `appMatchesFilter(item, filter, query)` — filtro de lista de apps
- `removeFromSelectionWithRollback(currentIds, idToRemove, saveFn)` — remoção com rollback

