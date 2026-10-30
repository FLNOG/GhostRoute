# GhostRoute

Para continuar o desenvolvimento em outra conversa ou com outra IA, leia primeiro [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md).

Protótipo Windows que oferece um túnel completo pelo cliente oficial WireGuard e um modo seletivo para Discord por meio do WireSock Secure Connect.

## Estado atual

- Interface Electron 45.
- Seleção inicial de uma configuração e migração da referência para o cofre DPAPI oficial do WireGuard.
- Instalação e remoção do serviço oficial `WireGuardTunnel$<nome>` com consentimento do UAC.
- Consulta periódica do serviço, handshake e transferência de dados.
- Consulta do IP público após conectar.
- Lista de aplicativos instalados com busca, ícones, seleção persistente e filtragem TCP/UDP por aplicativo.
- Serviços WireSock em inicialização manual: são iniciados ao conectar e parados ao encerrar o modo seletivo.
- Geração local de identidade WireGuard por dispositivo; a chave privada é protegida com DPAPI e somente a solicitação pública pode ser copiada.
- O GhostRoute não injeta código nem acessa processos de jogos, mas o WireSock instala componentes de filtragem de rede no Windows.

## Segurança da configuração

Arquivos `.conf` contêm chaves privadas. O diretório `wireguard/`, arquivos `*.conf` e `*.conf.dpapi` estão ignorados pelo Git.

Depois da seleção, o GhostRoute usa o caminho `.conf.dpapi` mantido pelo WireGuard em `C:\Program Files\WireGuard\Data\Configurations`. A cópia exportada em texto puro não é apagada automaticamente; remova-a somente depois de validar que a conexão protegida funciona.

O modo seletivo usa automaticamente a identidade local provisionada para este computador; o caminho não aparece na interface. O GhostRoute cria `wireguard/wiresock.generated.conf`, remove a configuração DNS para não trocar o resolvedor do Windows inteiro e adiciona os aplicativos marcados em `AllowedApps`. Esses arquivos permanecem ignorados pelo Git e não podem ser distribuídos.

Para distribuição ainda será necessário provisionar uma identidade diferente para cada computador. A chave privada nunca deve ser incorporada ao JavaScript ou ao instalador. A versão para amigos deverá gerar a chave localmente e cadastrar apenas a chave pública na VPS.

Na seção **Identidade do dispositivo**, o botão **Gerar solicitação** cria essa identidade sem substituir o perfil de teste atual. O status permanece `pending` até que a chave pública seja cadastrada na VPS e um endereço interno seja atribuído.

Depois do cadastro, **Ativar identidade** salva somente o endereço interno junto da chave DPAPI. Ao conectar, o perfil WireGuard em texto puro existe apenas durante a importação no WireSock e é removido imediatamente depois.

## Executar

Requisitos:

- Windows 10 ou 11.
- Node.js.
- WireGuard oficial para Windows instalado.
- WireSock Secure Connect completo instalado.
- Uma configuração de teste válida e exclusiva.

```powershell
npm install
npm run check
npm start
```

Na interface:

1. Selecione o `.conf` local.
2. Feche jogos competitivos e anticheats no primeiro teste.
3. Clique em **Conectar**.
4. Aceite a solicitação de administrador do Windows.
5. Confirme handshake, tráfego e IP público.
6. Execute os diagnósticos de DNS e IPv6.
7. Clique em **Desconectar** e aceite a segunda solicitação.

### Testar aplicativos selecionados

1. Garanta que a VPN completa está desconectada.
2. Marque um ou mais aplicativos na lista; use a busca ou a opção manual se necessário.
3. Encerre completamente todos os aplicativos marcados.
4. Clique em **Iniciar selecionados**.
5. O GhostRoute gera `AllowedApps`, conecta o WireSock e abre os aplicativos.
6. Teste os recursos de rede de cada aplicativo.
7. Confirme em outro navegador que o restante do computador continua usando seu IP normal.
8. Use **Encerrar modo seletivo**. Se o WireSock cair, o GhostRoute encerra o Discord para evitar tráfego direto.

## Limitações

- A conexão atual é full-tunnel; ela afeta todo o tráfego IPv4 abrangido por `AllowedIPs`.
- O estado `Conectado` confirma o serviço em execução. Handshake e IP são mostrados separadamente para evitar uma falsa confirmação de conectividade.
- IPv6 é diagnosticado, mas ainda não é bloqueado nem encaminhado pelo túnel IPv4.
- O IP público usa temporariamente `api.ipify.org` como diagnóstico externo.
- Cancelar o UAC pode aparecer como erro genérico dependendo da versão do Windows.
- Roteamento exclusivo do Discord ainda precisa ser validado para voz, câmera e compartilhamento nesta máquina.
- O WireSock usa um filtro de rede instalado no Windows. Feche jogos competitivos e anticheats durante os testes; não há garantia de compatibilidade ou de ausência de alertas.
- O driver `ndiswgc` permanece carregado: descarregá-lo interrompeu a rede nos testes. Parar os serviços remove os processos, mas não torna o driver invisível para anticheats.
- Não há instalador nem helper privilegiado dedicado nesta fase.

## Componentes de terceiros

O protótipo seletivo utiliza wireproxy 1.1.3, licenciado sob ISC. O binário Windows foi obtido da release oficial e conferido contra o checksum SHA-256 publicado:

```text
bce041ea9fe0f8a3351301dcbe29cdf6a523bb25cf9c62f17ebb5699a8051d0f
```

A licença está em `vendor/wireproxy/LICENSE`.

O modo seletivo atual usa a CLI de controle incluída no WireSock Secure Connect 3.8.1, instalado pelo pacote oficial `NTKERNEL.WireSockVPNClient`. O wireproxy permanece no projeto apenas como referência do protótipo anterior e não é iniciado pelo fluxo atual.

## Próximas etapas

1. Validar conexão e desconexão com a configuração de desenvolvimento.
2. Melhorar diagnóstico de handshake, DNS, IPv6 e recuperação.
3. Criar um helper privilegiado mínimo para evitar elevar a interface Electron.
4. Preparar instalador sem incluir credenciais.
5. Projetar provisionamento individual e revogação de peers.
6. Adicionar suporte especializado a aplicativos da Microsoft Store.
