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

**Campo `server` (todas as rotas deste grupo, desde 2026-11-16):** com mais de um hbbs (redundância), cada um sobe com `CONTROL_API_SERVER_NAME=<host público em minúsculas>` (ex.: `brremoteserver.brproj.com.br`, `brremoteserverb.brproj.com.br`) e manda esse valor como `"server"` em todo request. Sem a variável o campo **não é enviado** (ausente, nunca `""`): trate como "servidor desconhecido". Uma mesma máquina registrada em dois hbbs chega em `/peers/seen` pelos dois, com `server` diferente — é a mesma máquina (upsert por `id`), guarde o "visto em" **por servidor**. O mesmo host aparece no heartbeat do client (`rendezvous`, `servers[].host`), sem normalização.

### POST /tokens/verify

Chamado a cada tentativa de conexão de um controlador (com cache de `CONTROL_API_CACHE_SECS`, default 60s). **Precisa responder rápido** — o hbbs usa timeout de `CONTROL_API_TIMEOUT_MS` (default 2500ms).

Request:

```json
{ "token": "<token que o client enviou>", "ip": "200.150.10.20", "server": "brremoteserver.brproj.com.br" }
```

- `server` (opcional) = hbbs que está perguntando; informativo, não muda a decisão.
- `ip` = IP público de origem do pedido de conexão. Use para auditoria/cruzamento com o IP do login (detecção de token vazado). Não precisa reprovar por IP diferente se não quiser.

Respostas:

- **200** → atendente autorizado. Body opcional `{ "user": "douglas" }` — o nome aparece nos logs do hbbs.
- **403** → token vazio na sua base, inválido, revogado ou usuário desativado. (Body ignorado.)
- Qualquer outro status ou timeout → o hbbs trata como "API indisponível" e aplica `CONTROL_API_FAIL_OPEN` (`N` = bloqueia, `Y` = libera).

Observação: token **vazio** nunca chega aqui — o hbbs já bloqueia antes, com mensagem pedindo login.

#### API fora do ar: validação offline do token JWT (desde 2026-11-16)

Com a API fora (timeout ou status inesperado), o hbbs tenta validar **sozinho** o token do atendente,
se ele for um JWT e se `CONTROL_API_JWT_KEYS` estiver configurada:

- O JWT é o que o `/api/login` (e a renovação em `/api/currentUser`) devolve em `access_token`:
  header `{"alg":"EdDSA","typ":"JWT","kid":"k1"}`, payload com `sid` (o token opaco de sessão),
  `sub` (código do login), `pc` (ID RustDesk do PC do atendente), `name` (usuário, vai para o log do
  hbbs), `iat` e `exp` (7 dias, renovados a cada contato com a API). Assinatura Ed25519 sobre
  `header.payload`.
- hbbs confere assinatura (chave pública pelo `kid`) e `exp` com folga de 60 s. Válido → libera e
  cacheia por `CONTROL_API_CACHE_SECS`; vencido → bloqueia com "sua sessão expirou"; assinatura ou
  `kid` errados → bloqueia com "servidor de autorização indisponível".
- **Com a API respondendo, o `exp` é ignorado pelo hbbs**: quem decide é o `/tokens/verify` (200/403).
  A API também não precisa conferir assinatura: ela usa o `sid` de dentro do JWT.
- Token **opaco** (sem os dois pontos do JWT) com a API fora continua como sempre
  (`CONTROL_API_FAIL_OPEN`, default bloqueia).
- O que a queda congela: revogação (atendente cortado segue até o `exp`), trava de acessos
  simultâneos, auditoria `/connections/attempt` (fire-and-forget, perde), e o `user` do log vem do
  claim `name`.
- Rotação de chave: `CONTROL_API_JWT_KEYS` aceita várias (`k1=...;k2=...`). Publicar a nova nos
  hbbs **antes** de a API passar a assinar com ela; tirar a velha só depois de 7 dias.
- Códigos novos em `/connections/attempt` → `result`: `jwt_expired` e `jwt_invalid` (ambos só
  ocorrem com a API fora).

### POST /peers/seen

Telemetria/inventário — chamado quando qualquer peer (controlado ou controlador) se registra no hbbs. Com throttle por ID (`CONTROL_API_SEEN_SECS`, default 300s). Fire-and-forget: a resposta é ignorada (não-2xx só gera log). Nunca bloqueia nada.

Request:

```json
{ "id": "123456789", "ip": "200.150.10.20", "server": "brremoteserver.brproj.com.br" }
```

Comportamento esperado (upsert):

- ID novo → cadastra com status "pendente" (vira o inventário de máquinas vistas pelo servidor).
- ID existente → atualiza `last_seen` e `ip`.
- Com `server`: atualiza também o "visto em" daquele servidor (par `id` + `server`). Sem `server`: só o geral.

### POST /peers/registro

Dono do ID — chamado a cada `RegisterPk` (registro da chave de uma máquina controlada: no primeiro contato, quando o IP ou a porta mudam, e a cada conexão dos clients logados). Existe porque a unicidade do ID no hbbs vale só dentro de cada servidor: com dois hbbs, duas máquinas com o mesmo ID (MAC igual, `BRRemote.toml` copiado) podem ficar uma em cada um sem que nenhuma receba `UUID_MISMATCH`. Como os dois hbbs perguntam à mesma API, a unicidade passa a ser uma só.

**Precisa responder rápido**: o hbbs espera a resposta antes de aceitar o registro, com timeout de `CONTROL_API_REGISTER_TIMEOUT_MS` (default 1500ms), e cacheia o par `id`+`uuid` aceito por `CONTROL_API_REGISTER_CACHE_SECS` (default 300s).

Request:

```json
{ "id": "206524240", "uuid": "MjZmZGJkZTctZThlZS00NTE2LTgwYjctOTBlMjk4ZGQ4NTFj", "ip": "189.113.249.64", "server": "brremoteserver.brproj.com.br" }
```

- `id` (até 30 caracteres) e `uuid` (até 100) são obrigatórios. `uuid` = machine-uid da máquina em **base64**, o mesmo valor que o app manda no `/api/login` e no registro do catálogo.
- `ip` = IP público de onde a máquina se registrou; `server` como nas outras rotas (ausente sem `CONTROL_API_SERVER_NAME`). Os dois são o que mostra de onde veio cada conflito.

Respostas:

- **200** `{ "ok": true }` → o ID não tinha dono (este `uuid` passa a ser o dono) ou o `uuid` é o dono. O hbbs aceita o registro.
- **200** `{ "ok": false, "motivo": "uuid_mismatch" }` → o ID pertence a outro `uuid`. A API grava o conflito sempre. O que o hbbs faz depende de `CONTROL_API_REGISTER_ENFORCE`: `N` (default) só registra no log e aceita; `Y` responde `UUID_MISMATCH` ao client, que sorteia um ID novo de 10 dígitos e se registra de novo.
- 400 (sem `id`/`uuid`), 401, 404 (rota ainda não publicada), 5xx, timeout ou corpo sem `ok` → **fail-open**: o hbbs aceita o registro como antes e loga. A rota nunca impede uma máquina de se registrar por indisponibilidade.

Corrida entre os dois hbbs registrando o mesmo ID novo no mesmo instante: a API garante um dono só (chave primária) e a segunda chamada recebe a resposta certa, não 500.

Kill switch no hbbs: `CONTROL_API_REGISTER=N` desliga só esta consulta.

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
| `server` | ausente | hbbs que autorizou/negou (`CONTROL_API_SERVER_NAME`). **Ausente** quando o hbbs não tem a variável. |

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
- **donos_de_id**: rustdesk_id (PK), uuid, criado_em, visto_em, servidor. Alimentada por `/peers/registro`; conflitos (`ok:false`) em lista própria para decidir qual máquina fica com o número.
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
