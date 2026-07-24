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

---

## Modelo de dados sugerido (mínimo)

- **users**: id, username, password_hash, ativo (bool), criado_em.
- **sessions**: token (opaco, ex: UUID/random 32 bytes), user_id, rustdesk_id, uuid_maquina, ip_login, criado_em, revogado_em (null = ativa). Sessão única = no login, revogar as sessões anteriores do mesmo user.
- **peers**: rustdesk_id (unique), ip, status (pendente/…), first_seen, last_seen. Alimentada por `/peers/seen`.

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
