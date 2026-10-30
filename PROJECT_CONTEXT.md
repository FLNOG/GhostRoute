# GhostRoute — Contexto de continuidade

Atualizado em: 30 de outubro de 2026 (revisão de segurança e testes automatizados)

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
src/vpn/installed-apps.js           descoberta de aplicativos
src/vpn/identity-manager.js         chaves, DPAPI e perfil temporário
src/vpn/wireguard-controller.js      modo VPN completa legado
src/vpn/network-diagnostics.js      DNS, IPv4 e IPv6
src/vpn/operation-guard.js          trava de concorrência pura (sem I/O)
src/shutdown-controller.js          coordenador idêmpotente de encerramento
src/app-cleanup.js                  fábrica da função de cleanup com injetáveis
src/tray-menu-state.js              lógica pura de estado do menu da bandeja
src/assets/ghostroute-ghost.png      símbolo oficial; ícone da janela, hero e bandeja
src/assets/ghostroute-wordmark.png   logotipo horizontal usado no cabeçalho
src/tests/ghost-route.test.js       testes automatizados (72 casos, Node 18+)
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
7. Menu “Desconectar VPN”: evita cliques concorrentes, exibe erro sem silenciá-lo.
8. `src/app-cleanup.js`: fábrica `createCleanupFn()` com dependências injetáveis para testes.
9. **Correção crítica**: ShutdownController reescrito com máquina de 5 estados (`idle`→`cleaning`→`cleaned`→`quitting`→`done`).
   - `_allowWindowClose=true` definido ANTES de `quitFn()` para que `app.quit()` não bloqueie o próprio encerramento.
   - Se `quitFn` lançar: `state→cleaned`, Tray preservado, cleanup não se repete.
   - `destroyTrayFn` chamado APÓS `quitFn` (evita app invisvel e sem menu em falha).
10. **Testes**: 82 casos, 0 falhas, ~145 ms (grupos A–F; grupo F é a máquina de estados).

