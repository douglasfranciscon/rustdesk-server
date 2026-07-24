# Plano: RustDesk Server customizado com autorização de controlador

## Objetivo

- Qualquer computador pode ser **controlado** (nenhuma restrição do lado B).
- Quem vai **controlar** (prestar suporte) precisa estar aprovado pela minha própria API antes de poder abrir uma conexão.
- Sem depender de forks de terceiros (ex: `lejianwen/rustdesk-api`) — o enforcement mora no meu próprio fork do `rustdesk-server` oficial.
- Client continua sendo o build customizado padrão (logo, servidor, chave **e URL do API server** embutidos via gerador — **não precisa mexer no código do client**).

## Decisão: autorização por token (login nativo do client)

Descobertas que mudaram o plano original:

- O `PunchHoleRequest` **não carrega o ID de quem pede a conexão** (só o do alvo), e chega por TCP com porta diferente do registro UDP. Identificar o controlador por endereço só seria possível via IP — ambíguo com NAT compartilhado e inviável com CGNAT (comum no Brasil).
- Em compensação, o `PunchHoleRequest` (campo `token`) e o `RequestRelay` (campo `token`) carregam o **access_token do login nativo do client** (Configurações → Conta). Esse login aponta pro "API server" embutido no build customizado — ou seja, **minha API**.

Fluxo decidido:

1. Atendente faz login no app (uma vez; auto-login mantém). O client chama `POST /api/login` na minha API, que devolve o `access_token`. No login o client envia também o **ID RustDesk e UUID da máquina** — dá pra aplicar política de sessão única (recusar segundo login ou revogar o token anterior).
2. Todo pedido de conexão do client carrega o token. Meu fork do hbbs valida na minha API: **200 libera, 403 bloqueia**. Token vazio (não logou) = bloqueado, com mensagem exibida no client.
3. Lado B (controlado) nunca loga e não sofre nenhuma restrição.
4. Revogação: excluir/bloquear o usuário na API derruba o acesso em até 60s (TTL do cache do hbbs).

## O que foi implementado no hbbs (fork)

- **`src/control_api.rs`** (módulo novo): config via env vars, cliente HTTP (`reqwest`), cache de tokens, throttle de telemetria, registro de bloqueios para diagnóstico.
- **Gate no `handle_punch_hole_request`** ([src/rendezvous_server.rs](src/rendezvous_server.rs)): valida `ph.token` logo após a checagem de `licence_key`; negado → `PunchHoleResponse.other_failure` com a mensagem (client exibe).
- **Gate no handler de `RequestRelay`**: mesmo bloqueio (senão seria bypass — client modificado pediria relay direto sem punch hole); negado → `RelayResponse.refuse_reason`.
- **Telemetria**: `RegisterPeer`/`RegisterPk` reportam `POST /peers/seen {id, ip}` (fire-and-forget, com throttle; API fora do ar não afeta nada).
- **Console local**: comando `control-api` (ou `ca`) mostra config, cache de tokens e últimos bloqueios.

### Configuração (env vars / .env / flags)

| Variável | Default | Função |
|---|---|---|
| `CONTROL_API_URL` | vazio | Base da API. **Vazio = feature desligada** (hbbs 100% vanilla). |
| `CONTROL_API_TOKEN` | vazio | Enviado como `Authorization: Bearer` nas chamadas hbbs → API. |
| `CONTROL_API_FAIL_OPEN` | `N` | `Y` = API fora do ar libera; `N` = bloqueia (fail-closed). |
| `CONTROL_API_TIMEOUT_MS` | `2500` | Timeout das chamadas à API. |
| `CONTROL_API_CACHE_SECS` | `60` | TTL do cache por token (= tempo máx. p/ revogação valer). |
| `CONTROL_API_SEEN_SECS` | `300` | Throttle do report "peer visto" por ID. |

## Contrato da minha API (a desenvolver)

### Grupo 1 — contrato do client RustDesk (formato ditado pelo client)

- `POST /api/login` — body: `username`, `password`, `id`, `uuid`. Resposta: `{"type": "access_token", "access_token": "...", "user": {"name": "..."}}`.
- `POST /api/currentUser` — valida `Authorization: Bearer`, devolve o usuário (401 desloga o client).
- `POST /api/logout` — 200 simples.
- `POST /api/heartbeat`, `POST /api/sysinfo` — responder `200 {}` (opcional aproveitar como telemetria).
- `/api/ab/...` (catálogo) — opcional.
- Referência de formato: docs do `lejianwen/rustdesk-api` (mesmo contrato, mas implementado na minha stack).

### Grupo 2 — contrato hbbs → minha API (formato meu)

- `POST /tokens/verify` — body `{"token": "...", "ip": "<ip de origem>"}`. **200** = aprovado (body opcional `{"user": "nome"}` pros logs do hbbs); **403** = negado. Outro status/timeout = falha (aplica `CONTROL_API_FAIL_OPEN`). O IP permite cruzar com a máquina do login (auditoria / token roubado).
- `POST /peers/seen` — body `{"id": "...", "ip": "..."}`. Upsert: novo = "pendente", existente = atualiza `last_seen`.

## Compilar sem Docker

- `git submodule update --init` (o `libs/hbb_common` é submódulo — sem ele não compila).
- `rustup install stable` + `cargo build --release` → `hbbs`, `hbbr`, `rustdesk-utils` em `target/release/`.
- No Windows sem Visual Studio Build Tools: usar toolchain GNU (`rustup default stable-gnu`).
- Docker só para empacotar deploy (pode ser via CI depois).

## Como manter atualizado (não travar em versão velha)

1. Fork do `rustdesk/rustdesk-server` no GitHub (meu controle).
2. `git remote add upstream https://github.com/rustdesk/rustdesk-server.git`.
3. Mudanças concentradas: 1 módulo novo + poucos pontos de `rendezvous_server.rs` → conflito raro.
4. Atualizar: `git fetch upstream` + merge/rebase. Automatizável com GitHub Actions (avisa só quando der conflito).

## Ponto de atenção legal (licença AGPL-3.0)

- Rodando versão modificada que os atendentes acessam pela rede, a AGPL exige disponibilizar o fonte modificado a quem interage com o serviço — repo privado com acesso aos atendentes resolve.

## Próximos passos

- [x] Definir o contrato da API (grupos 1 e 2 acima)
- [x] Implementar validação de token no hbbs (punch hole + relay) com cache e timeout
- [x] Implementar telemetria `peers/seen`
- [x] Fail-open/closed configurável (`CONTROL_API_FAIL_OPEN`, default fechado)
- [ ] Desenvolver a minha API (login do client + verify + seen + telas de gestão de atendentes)
- [ ] Embutir a URL do API server no gerador do client customizado
- [ ] Configurar fork + upstream remote + workflow de atualização
- [ ] Disponibilizar o código-fonte modificado (AGPL) pros atendentes
