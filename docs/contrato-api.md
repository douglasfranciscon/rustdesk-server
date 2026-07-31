# Contrato da API de Controle (BR Suporte)

API que autoriza controladores do RustDesk. Consumida por dois clientes distintos:

- **O client RustDesk** (app dos atendentes) — endpoints do **Grupo 1**, formato ditado pelo client.
- **O hbbs customizado** (este fork) — endpoints do **Grupo 2**, formato definido por nós.

Todas as rotas recebem e devolvem JSON (`Content-Type: application/json`).

---

## Grupo 1 — endpoints chamados pelo client RustDesk

A URL base é a que for embutida como "API server" no gerador do client customizado (ex: `https://api.suaempresa.com.br`). Os nomes de campo da **resposta** do login precisam ser exatamente estes (o client faz o parse). Referência do mesmo contrato: docs do `lejianwen/rustdesk-api`.

### POST /api/login

Request (campos principais; o client pode mandar outros — ignorar o que não usar):

```json
{
  "username": "douglas",
  "password": "senha",
  "id": "123456789",
  "uuid": "b2c3...",
  "autoLogin": true,
  "type": "account",
  "deviceInfo": { "os": "windows", "type": "client", "name": "PC-ATENDENTE" }
}
```

- `id` = ID RustDesk da máquina onde o login acontece; `uuid` = UUID da máquina.
  **É aqui que dá pra aplicar sessão única**: se o usuário já tem sessão ativa em outra máquina, ou recusa o login, ou revoga o token anterior (recomendado: "último login vence").

Resposta sucesso (200):

```json
{
  "type": "access_token",
  "access_token": "<token opaco gerado pela API>",
  "user": { "name": "douglas" }
}
```

Resposta falha (200 com corpo de erro — padrão do client):

```json
{ "error": "Usuário ou senha inválidos" }
```

### POST /api/currentUser

Header `Authorization: Bearer <access_token>`. Body: `{ "id": "...", "uuid": "..." }`.

- Token válido → 200 `{ "name": "douglas" }`
- Token inválido/revogado → **401** (isso faz o client voltar ao estado "deslogado" — é o que derruba a sessão antiga na política "último login vence").

### POST /api/logout

Header Bearer. Invalida o token. Resposta: 200 `{}`.

### POST /api/heartbeat e POST /api/sysinfo

O client envia periodicamente (id, uuid, versão, info de sistema). Responder 200 `{}`.
Opcional: aproveitar como telemetria ("atendente online").

### POST /api/audit/conn (opcional)

O client reporta conexões feitas. Responder 200 `{}` se não quiser processar.

Não confundir com `/connections/attempt` (Grupo 2): este aqui é reportado **pelo app do atendente** (pode ser burlado e não existe se o app não estiver logado); aquele é reportado **pelo hbbs**, é a fonte confiável e é o único que enxerga as tentativas bloqueadas.

### /api/ab (catálogo de endereços — opcional)

Se não implementar, só a aba "Catálogo" do app fica sem função. Conexões não dependem disso.

---

## Grupo 2 — endpoints chamados pelo hbbs (este fork)

URL base = env var `CONTROL_API_URL` do hbbs. Se `CONTROL_API_TOKEN` estiver configurado no hbbs, toda chamada leva `Authorization: Bearer <CONTROL_API_TOKEN>` — **valide esse header** para que só o hbbs consiga chamar estas rotas.

### POST /tokens/verify

Chamado a cada tentativa de conexão de um controlador (com cache de `CONTROL_API_CACHE_SECS`, default 60s). **Precisa responder rápido** — o hbbs usa timeout de `CONTROL_API_TIMEOUT_MS` (default 2500ms).

Request:

```json
{ "token": "<token que o client enviou>", "ip": "200.150.10.20" }
```

- `ip` = IP público de origem do pedido de conexão. Use para auditoria/cruzamento com o IP do login (detecção de token vazado). Não precisa reprovar por IP diferente se não quiser.

Respostas:

- **200** → atendente autorizado. Body opcional `{ "user": "douglas" }` — o nome aparece nos logs do hbbs.
- **403** → token vazio na sua base, inválido, revogado ou usuário desativado. (Body ignorado.)
- Qualquer outro status ou timeout → o hbbs trata como "API indisponível" e aplica `CONTROL_API_FAIL_OPEN` (`N` = bloqueia, `Y` = libera).

Observação: token **vazio** nunca chega aqui — o hbbs já bloqueia antes, com mensagem pedindo login.

### POST /peers/seen

Telemetria/inventário — chamado quando qualquer peer (controlado ou controlador) se registra no hbbs. Com throttle por ID (`CONTROL_API_SEEN_SECS`, default 300s). Fire-and-forget: a resposta é ignorada (não-2xx só gera log). Nunca bloqueia nada.

Request:

```json
{ "id": "123456789", "ip": "200.150.10.20" }
```

Comportamento esperado (upsert):

- ID novo → cadastra com status "pendente" (vira o inventário de máquinas vistas pelo servidor).
- ID existente → atualiza `last_seen` e `ip`.

### POST /connections/attempt

Auditoria — chamado a cada tentativa de conexão de um controlador, **autorizada ou bloqueada**. Fire-and-forget: a resposta é completamente ignorada (não-2xx só gera log). **Nunca bloqueia, atrasa nem altera uma conexão** — erro, timeout, 404 ou API fora do ar não têm nenhuma consequência. Se você precisa recusar conexões, isso é feito no `/tokens/verify` respondendo 403.

Request:

```json
{
  "target_id": "123456789",
  "ip": "200.150.10.20",
  "token": "a1b2c3d4e5f6...",
  "user": "douglas",
  "result": "allowed",
  "reason": null,
  "kind": "punch_hole",
  "conn_type": "DEFAULT_CONN",
  "version": "1.4.1",
  "via": "tcp",
  "at": "2026-07-31T12:34:56Z"
}
```

| Campo | Nulo? | Significado |
|---|---|---|
| `target_id` | não | ID RustDesk da **máquina alvo** (quem seria controlado). |
| `ip` | não | IP público de origem da tentativa (o IP do atendente). |
| `token` | não | `access_token` da sessão do atendente, o mesmo que chega em `/tokens/verify`. **String vazia `""` quando o atendente não estava logado.** É a única forma de identificar quem tentou — o protocolo do RustDesk não transmite o ID do controlador. |
| `user` | sim | Nome que a API devolveu no `/tokens/verify`. `null` quando o token era inválido, quando o verify respondeu 200 sem `user`, ou quando o `CONTROL_API_FAIL_OPEN` liberou sem consulta. |
| `result` | não | `allowed` \| `login_required` \| `denied` \| `api_down` (ver abaixo). |
| `reason` | sim | Mensagem exibida ao atendente no bloqueio. `null` quando `allowed`. |
| `kind` | não | `punch_hole` (conexão direta/P2P) ou `relay` (via servidor de relay). |
| `conn_type` | não | `DEFAULT_CONN` (acesso remoto), `FILE_TRANSFER`, `PORT_FORWARD`, `RDP`, `VIEW_CAMERA`, `TERMINAL`. |
| `version` | sim | Versão do client RustDesk. `null` quando `kind = "relay"`. |
| `via` | não | `tcp` ou `ws` (WebSocket). |
| `at` | não | Timestamp UTC RFC3339 com segundos e sufixo `Z`. |

Valores de `result`:

| Valor | Quando acontece |
|---|---|
| `allowed` | O `/tokens/verify` respondeu 200 (ou o cache dele) e a conexão foi liberada. |
| `login_required` | O client mandou token vazio (atendente não logado). Esse caso **nunca chega no `/tokens/verify`** — o hbbs bloqueia antes. |
| `denied` | O `/tokens/verify` respondeu 403 (token inválido, revogado ou usuário desativado). |
| `api_down` | O `/tokens/verify` deu timeout ou status inesperado e o hbbs bloqueou por fail-closed. **Alerta de indisponibilidade da API.** |

Trate `result` como campo aberto: se um valor desconhecido chegar no futuro, grave em vez de rejeitar.

Volume e duplicidade: o client reenvia o `PunchHoleRequest` várias vezes e ainda pede relay para a mesma conexão. O hbbs deduplica por `(ip + target_id + result)` durante `CONTROL_API_ATTEMPT_DEDUPE_SECS` (default 60s), então uma tentativa real gera **1 evento**, não 3–5. Se o desfecho mudar (`denied` e depois `allowed`), os dois eventos chegam — a mudança de resultado quebra o dedupe de propósito. Ainda assim a rota deve tolerar reentrega do mesmo evento.

Ao gravar: resolver o `token` para `user_id`/`session_id` (mesma consulta do verify) e **não armazenar o token em claro**. Token não encontrado (normal em `denied`) ou vazio (`login_required`) → gravar com `user_id` nulo; o evento não pode ser descartado por isso, ele é justamente o registro de uma tentativa não autorizada.

Kill switch no hbbs: `CONTROL_API_ATTEMPTS=N` desliga só estes eventos, sem afetar o resto.

---

## Modelo de dados sugerido (mínimo)

- **users**: id, username, password_hash, ativo (bool), criado_em.
- **sessions**: token (opaco, ex: UUID/random 32 bytes), user_id, rustdesk_id, uuid_maquina, ip_login, criado_em, revogado_em (null = ativa). Sessão única = no login, revogar as sessões anteriores do mesmo user.
- **peers**: rustdesk_id (unique), ip, status (pendente/…), first_seen, last_seen. Alimentada por `/peers/seen`.
- **connection_attempts**: at, received_at, target_id, ip, user_id (null), session_id (null), user_name (null), result, reason (null), kind, conn_type, version (null), via. Alimentada por `/connections/attempt`; índices por `at`, `user_id`, `target_id`.

## Regras de negócio que ficam na API (não no hbbs)

- Cadastro/desativação de atendentes; troca de senha.
- Política de sessão única (via `id`/`uuid` do login).
- Revogação: desativar usuário ou revogar sessão → `/tokens/verify` passa a responder 403 → acesso cai em até 60s.
- (Opcional) checagem de IP do verify vs IP do login.

## Segurança

- Servir tudo em HTTPS.
- Validar `Authorization: Bearer <CONTROL_API_TOKEN>` nas rotas do Grupo 2.
- `access_token` opaco e aleatório (não precisa ser JWT; a validação é sempre server-side no verify).
- Rate-limit no `/api/login` (força bruta).
