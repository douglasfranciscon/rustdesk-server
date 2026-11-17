// Integration with the external control API that authorizes controllers.
// Disabled entirely when CONTROL_API_URL is empty (vanilla behavior).
use crate::common::*;
use hbb_common::{log, tokio, tokio::sync::Mutex};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const MSG_LOGIN_REQUIRED: &str = "Acesso negado: faça login no aplicativo para conectar.";
const MSG_DENIED: &str = "Acesso negado: usuário não autorizado.";
const MSG_API_DOWN: &str = "Servidor de autorização indisponível. Tente novamente em instantes.";
const MSG_JWT_EXPIRED: &str =
    "Servidor de autorização indisponível e sua sessão expirou: faça login novamente quando ele voltar.";
/// Tolerância de relógio entre a API (que assina) e este hbbs ao conferir `exp`.
const JWT_LEEWAY_SECS: u64 = 60;
const MAX_CACHE_ENTRIES: usize = 10_000;
const MAX_BLOCK_ENTRIES: usize = 100;

struct Config {
    url: String,
    token: String,
    fail_open: bool,
    timeout_ms: u64,
    cache_secs: u64,
    seen_secs: u64,
    attempts: bool,
    attempt_dedupe_secs: u64,
    /// Nome publico deste hbbs (CONTROL_API_SERVER_NAME), enviado como `server` a
    /// API para distinguir os servidores redundantes. Vazio = campo nao enviado.
    server_name: String,
    /// Chaves públicas Ed25519 (kid -> chave) que validam o token JWT do atendente
    /// OFFLINE, só quando a API não responde (CONTROL_API_JWT_KEYS). Vazio = sem
    /// validação offline: API fora aplica `fail_open` como sempre.
    jwt_keys: HashMap<String, jsonwebtoken::DecodingKey>,
    /// CONTROL_API_REGISTER (default Y): a cada RegisterPk, confirma em
    /// POST /peers/registro que o ID pertence a esta máquina (uuid). N = não consulta.
    register: bool,
    /// CONTROL_API_REGISTER_ENFORCE: Y = ID de outra máquina recebe UUID_MISMATCH
    /// (o client sorteia outro ID); N (default) = só registra o conflito no log.
    register_enforce: bool,
    register_timeout_ms: u64,
    /// TTL do cache (id -> uuid aceito) que evita repetir a consulta.
    register_cache_secs: u64,
}

/// CONTROL_API_JWT_KEYS = "k1=<base64 SPKI ou PEM>;k2=..." (separador `;` ou `,`).
/// Aceita a linha do meio do PEM "PUBLIC KEY" (SPKI em base64) ou o PEM inteiro.
fn parse_jwt_keys(raw: &str) -> HashMap<String, jsonwebtoken::DecodingKey> {
    let mut keys = HashMap::new();
    for entry in raw.split([';', ',']).map(str::trim).filter(|e| !e.is_empty()) {
        let Some((kid, value)) = entry.split_once('=') else {
            log::error!("BR_SUPORTE: CONTROL_API_JWT_KEYS: entrada sem '=' ignorada: {:?}", entry);
            continue;
        };
        let (kid, value) = (kid.trim(), value.trim());
        let pem = if value.contains("-----BEGIN") {
            value.replace("\\n", "\n")
        } else {
            format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", value)
        };
        match jsonwebtoken::DecodingKey::from_ed_pem(pem.as_bytes()) {
            Ok(key) => {
                keys.insert(kid.to_owned(), key);
            }
            Err(err) => log::error!(
                "BR_SUPORTE: CONTROL_API_JWT_KEYS: chave kid={} inválida, ignorada: {}",
                kid,
                err
            ),
        }
    }
    keys
}

static CONFIG: Lazy<Config> = Lazy::new(|| {
    let config = Config {
        url: get_arg("control_api_url").trim_end_matches('/').to_owned(),
        token: get_arg("control_api_token"),
        fail_open: get_arg("control_api_fail_open").to_uppercase() == "Y",
        timeout_ms: get_arg_or("control_api_timeout_ms", "2500".to_owned())
            .parse()
            .unwrap_or(2500),
        cache_secs: get_arg_or("control_api_cache_secs", "60".to_owned())
            .parse()
            .unwrap_or(60),
        seen_secs: get_arg_or("control_api_seen_secs", "300".to_owned())
            .parse()
            .unwrap_or(300),
        // ligado por default: o POST é fire-and-forget, então subir o hbbs antes
        // de a API ter a rota só gera warning de 404
        attempts: get_arg_or("control_api_attempts", "Y".to_owned()).to_uppercase() != "N",
        attempt_dedupe_secs: get_arg_or("control_api_attempt_dedupe_secs", "60".to_owned())
            .parse()
            .unwrap_or(60),
        server_name: get_arg("control_api_server_name").trim().to_lowercase(),
        jwt_keys: parse_jwt_keys(&get_arg("control_api_jwt_keys")),
        register: get_arg_or("control_api_register", "Y".to_owned()).to_uppercase() != "N",
        register_enforce: get_arg("control_api_register_enforce").to_uppercase() == "Y",
        register_timeout_ms: get_arg_or("control_api_register_timeout_ms", "1500".to_owned())
            .parse()
            .unwrap_or(1500),
        register_cache_secs: get_arg_or("control_api_register_cache_secs", "300".to_owned())
            .parse()
            .unwrap_or(300),
    };
    if config.url.is_empty() {
        log::info!("BR_SUPORTE: CONTROL_API_URL vazio, feature DESLIGADA (comportamento vanilla)");
    } else {
        log::info!(
            "BR_SUPORTE: LIGADO url={} server_name={:?} jwt_kids={:?} fail_open={} timeout_ms={} cache_secs={} seen_secs={} attempts={} attempt_dedupe_secs={} register={} register_enforce={} register_timeout_ms={} register_cache_secs={} auth_bearer={}",
            config.url,
            config.server_name,
            config.jwt_keys.keys().collect::<Vec<_>>(),
            config.fail_open,
            config.timeout_ms,
            config.cache_secs,
            config.seen_secs,
            config.attempts,
            config.attempt_dedupe_secs,
            config.register,
            config.register_enforce,
            config.register_timeout_ms,
            config.register_cache_secs,
            !config.token.is_empty()
        );
    }
    config
});

static HTTP: Lazy<Option<reqwest::Client>> = Lazy::new(|| {
    match reqwest::Client::builder()
        .timeout(Duration::from_millis(CONFIG.timeout_ms))
        .build()
    {
        Ok(client) => Some(client),
        Err(err) => {
            log::error!("BR_SUPORTE: failed to build http client: {}", err);
            None
        }
    }
});

/// Cliente com timeout próprio (mais curto) para a consulta do dono do ID, que é
/// aguardada no caminho do registro do peer.
static HTTP_REGISTER: Lazy<Option<reqwest::Client>> = Lazy::new(|| {
    match reqwest::Client::builder()
        .timeout(Duration::from_millis(CONFIG.register_timeout_ms))
        .build()
    {
        Ok(client) => Some(client),
        Err(err) => {
            log::error!("BR_SUPORTE: failed to build register http client: {}", err);
            None
        }
    }
});

struct TokenEntry {
    authorized: bool,
    user: Option<String>,
    tm: Instant,
}

struct BlockEntry {
    tm: Instant,
    from_ip: String,
    target_id: String,
    reason: String,
}

/// Why a connection attempt was refused. `message()` is what the client shows,
/// `code()` is what goes to the API audit event.
#[derive(Clone, Copy)]
pub enum Denial {
    LoginRequired,
    NotAuthorized,
    ApiDown,
    /// API fora e o JWT do atendente venceu (ou ainda não vale).
    JwtExpired,
    /// API fora e o JWT não confere (assinatura, kid desconhecido, alg, formato).
    JwtInvalid,
}

impl Denial {
    pub fn message(&self) -> &'static str {
        match self {
            Denial::LoginRequired => MSG_LOGIN_REQUIRED,
            Denial::NotAuthorized => MSG_DENIED,
            Denial::ApiDown | Denial::JwtInvalid => MSG_API_DOWN,
            Denial::JwtExpired => MSG_JWT_EXPIRED,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Denial::LoginRequired => "login_required",
            Denial::NotAuthorized => "denied",
            Denial::ApiDown => "api_down",
            Denial::JwtExpired => "jwt_expired",
            Denial::JwtInvalid => "jwt_invalid",
        }
    }
}

/// Um JWT tem três partes separadas por ponto; o token opaco da API não tem ponto.
fn looks_like_jwt(token: &str) -> bool {
    token.matches('.').count() == 2
}

/// Valida o JWT do atendente sem a API: assinatura Ed25519 com uma das chaves de
/// CONTROL_API_JWT_KEYS (pelo `kid` do header) e `exp` com folga. Devolve o nome
/// do atendente (claim `name`) para o log. Só é chamado quando a API não responde.
fn verify_jwt_offline(token: &str) -> Result<Option<String>, Denial> {
    use jsonwebtoken::{decode, decode_header, errors::ErrorKind, Algorithm, Validation};
    let header = decode_header(token).map_err(|err| {
        log::warn!("BR_SUPORTE: JWT offline: header inválido: {}", err);
        Denial::JwtInvalid
    })?;
    if header.alg != Algorithm::EdDSA {
        log::warn!("BR_SUPORTE: JWT offline: alg {:?} não é EdDSA", header.alg);
        return Err(Denial::JwtInvalid);
    }
    let kid = header.kid.unwrap_or_default();
    let Some(key) = CONFIG.jwt_keys.get(&kid) else {
        log::warn!(
            "BR_SUPORTE: JWT offline: kid={:?} desconhecido (conhecidos: {:?})",
            kid,
            CONFIG.jwt_keys.keys().collect::<Vec<_>>()
        );
        return Err(Denial::JwtInvalid);
    };
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.leeway = JWT_LEEWAY_SECS;
    validation.validate_exp = true;
    match decode::<serde_json::Value>(token, key, &validation) {
        Ok(data) => {
            let name = data
                .claims
                .get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_owned());
            Ok(name)
        }
        Err(err) => match err.kind() {
            ErrorKind::ExpiredSignature | ErrorKind::ImmatureSignature => {
                log::warn!("BR_SUPORTE: JWT offline: vencido ({})", err);
                Err(Denial::JwtExpired)
            }
            _ => {
                log::warn!("BR_SUPORTE: JWT offline: inválido ({})", err);
                Err(Denial::JwtInvalid)
            }
        },
    }
}

static TOKEN_CACHE: Lazy<Mutex<HashMap<String, TokenEntry>>> = Lazy::new(Default::default);
static SEEN_SENT: Lazy<Mutex<HashMap<String, Instant>>> = Lazy::new(Default::default);
static ATTEMPT_SENT: Lazy<Mutex<HashMap<String, Instant>>> = Lazy::new(Default::default);
static BLOCKS: Lazy<Mutex<Vec<BlockEntry>>> = Lazy::new(Default::default);
/// id -> (uuid em base64 aceito pela API, quando)
static REGISTER_CACHE: Lazy<Mutex<HashMap<String, (String, Instant)>>> =
    Lazy::new(Default::default);

#[inline]
pub fn is_enabled() -> bool {
    !CONFIG.url.is_empty()
}

/// Adds `"server": <CONTROL_API_SERVER_NAME>` to a JSON body when configured.
/// Without the variable the field is absent (never an empty string), so the API
/// can tell "unknown" from a named server.
fn with_server(mut body: serde_json::Value) -> serde_json::Value {
    if !CONFIG.server_name.is_empty() {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("server".to_owned(), CONFIG.server_name.clone().into());
        }
    }
    body
}

/// Checks whether the given client token belongs to an authorized controller.
/// Returns Ok(user name if reported by the API) to allow, Err(denial) to deny.
pub async fn check_token(token: &str, ip: &str) -> Result<Option<String>, Denial> {
    if !is_enabled() {
        return Ok(None);
    }
    if token.is_empty() {
        // TODO(debug-teste): logs verbosos desta fase de teste; remover depois
        log::info!("BR_SUPORTE: check_token ip={} token VAZIO -> bloqueado (login necessário)", ip);
        return Err(Denial::LoginRequired);
    }
    let token_prefix: String = token.chars().take(8).collect();
    let now = Instant::now();
    {
        let cache = TOKEN_CACHE.lock().await;
        if let Some(entry) = cache.get(token) {
            if now.duration_since(entry.tm).as_secs() < CONFIG.cache_secs {
                log::info!(
                    "BR_SUPORTE: check_token ip={} token={}... CACHE hit (age={}s) -> authorized={}",
                    ip,
                    token_prefix,
                    entry.tm.elapsed().as_secs(),
                    entry.authorized
                );
                return if entry.authorized {
                    Ok(entry.user.clone())
                } else {
                    Err(Denial::NotAuthorized)
                };
            }
        }
    }
    log::info!(
        "BR_SUPORTE: check_token ip={} token={}... sem cache, consultando {}/tokens/verify",
        ip,
        token_prefix,
        CONFIG.url
    );
    match call_verify(token, ip).await {
        Ok((authorized, user)) => {
            log::info!(
                "BR_SUPORTE: verify respondeu token={}... authorized={} user={:?} (cacheado por {}s)",
                token_prefix,
                authorized,
                user,
                CONFIG.cache_secs
            );
            let mut cache = TOKEN_CACHE.lock().await;
            if cache.len() >= MAX_CACHE_ENTRIES && !cache.contains_key(token) {
                let ttl = CONFIG.cache_secs;
                cache.retain(|_, e| now.duration_since(e.tm).as_secs() < ttl);
            }
            cache.insert(
                token.to_owned(),
                TokenEntry {
                    authorized,
                    user: user.clone(),
                    tm: now,
                },
            );
            if authorized {
                Ok(user)
            } else {
                Err(Denial::NotAuthorized)
            }
        }
        Err(err) if looks_like_jwt(token) && !CONFIG.jwt_keys.is_empty() => {
            // API fora: o JWT assinado por ela vale sozinho até vencer (janela que
            // a API renova a cada contato). Token opaco antigo cai no braço abaixo.
            let result = verify_jwt_offline(token);
            match &result {
                Ok(user) => log::warn!(
                    "BR_SUPORTE: verify FALHOU ({}) -> JWT válido OFFLINE token={}... user={:?} => LIBERADO",
                    err,
                    token_prefix,
                    user
                ),
                Err(denial) => log::warn!(
                    "BR_SUPORTE: verify FALHOU ({}) -> JWT offline recusado ({}) token={}... => BLOQUEADO",
                    err,
                    denial.code(),
                    token_prefix
                ),
            }
            if let Ok(user) = &result {
                let mut cache = TOKEN_CACHE.lock().await;
                if cache.len() >= MAX_CACHE_ENTRIES && !cache.contains_key(token) {
                    let ttl = CONFIG.cache_secs;
                    cache.retain(|_, e| now.duration_since(e.tm).as_secs() < ttl);
                }
                cache.insert(
                    token.to_owned(),
                    TokenEntry {
                        authorized: true,
                        user: user.clone(),
                        tm: now,
                    },
                );
            }
            result
        }
        Err(err) => {
            log::warn!(
                "BR_SUPORTE: verify FALHOU ({}) -> fail_open={} => {}",
                err,
                CONFIG.fail_open,
                if CONFIG.fail_open { "LIBERADO" } else { "BLOQUEADO" }
            );
            if CONFIG.fail_open {
                Ok(None)
            } else {
                Err(Denial::ApiDown)
            }
        }
    }
}

async fn call_verify(token: &str, ip: &str) -> Result<(bool, Option<String>), String> {
    let client = HTTP
        .as_ref()
        .ok_or_else(|| "http client unavailable".to_owned())?;
    let mut req = client
        .post(format!("{}/tokens/verify", CONFIG.url))
        .json(&with_server(serde_json::json!({ "token": token, "ip": ip })));
    if !CONFIG.token.is_empty() {
        req = req.bearer_auth(&CONFIG.token);
    }
    let started = Instant::now();
    let resp = req.send().await.map_err(|e| e.to_string())?;
    log::info!(
        "BR_SUPORTE: POST /tokens/verify -> HTTP {} em {}ms",
        resp.status().as_u16(),
        started.elapsed().as_millis()
    );
    match resp.status().as_u16() {
        200 => {
            let user = resp
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|v| v.get("user").and_then(|u| u.as_str()).map(|s| s.to_owned()));
            Ok((true, user))
        }
        403 => Ok((false, None)),
        status => Err(format!("unexpected status {}", status)),
    }
}

/// Reports a peer id/ip to the control API (inventory/telemetry only, never
/// blocks). Throttled per id by CONTROL_API_SEEN_SECS.
pub async fn report_seen(id: &str, ip: String) {
    // "(:test_hbbs:)" is the internal self-test peer, not a real machine
    if !is_enabled() || id.is_empty() || id == "(:test_hbbs:)" {
        return;
    }
    let now = Instant::now();
    {
        let mut sent = SEEN_SENT.lock().await;
        if let Some(tm) = sent.get(id) {
            if now.duration_since(*tm).as_secs() < CONFIG.seen_secs {
                // TODO(debug-teste): throttle é o caso comum (heartbeat a cada ~10s); debug pra não inundar
                log::debug!(
                    "BR_SUPORTE: peers/seen id={} suprimido pelo throttle ({}s restantes)",
                    id,
                    CONFIG.seen_secs.saturating_sub(now.duration_since(*tm).as_secs())
                );
                return;
            }
        }
        if sent.len() >= MAX_CACHE_ENTRIES && !sent.contains_key(id) {
            let ttl = CONFIG.seen_secs;
            sent.retain(|_, tm| now.duration_since(*tm).as_secs() < ttl);
        }
        sent.insert(id.to_owned(), now);
    }
    let id = id.to_owned();
    log::info!("BR_SUPORTE: peers/seen enviando id={} ip={}", id, ip);
    tokio::spawn(async move {
        if let Some(client) = HTTP.as_ref() {
            let mut req = client
                .post(format!("{}/peers/seen", CONFIG.url))
                .json(&with_server(serde_json::json!({ "id": id, "ip": ip })));
            if !CONFIG.token.is_empty() {
                req = req.bearer_auth(&CONFIG.token);
            }
            let started = Instant::now();
            match req.send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        log::info!(
                            "BR_SUPORTE: peers/seen id={} -> HTTP {} em {}ms",
                            id,
                            resp.status().as_u16(),
                            started.elapsed().as_millis()
                        );
                    } else {
                        log::warn!("BR_SUPORTE: peers/seen id={} returned {}", id, resp.status());
                    }
                }
                Err(err) => log::warn!("BR_SUPORTE: peers/seen id={} failed: {}", id, err),
            }
        }
    });
}

#[inline]
pub fn registration_enabled() -> bool {
    is_enabled() && CONFIG.register
}

/// Confirma na API de controle que o ID pertence a esta máquina (`uuid`), para a
/// unicidade do ID valer entre os hbbs redundantes e não só dentro de cada um.
///
/// Devolve `false` SÓ quando a API respondeu `{"ok":false}` e
/// CONTROL_API_REGISTER_ENFORCE=Y. API fora, 404, 400, timeout ou corpo estranho
/// = aceita (fail-open), com log. O uuid vai em base64, igual ao que o app manda
/// à API no login, então a mesma máquina tem o mesmo valor nos dois caminhos.
pub async fn check_registration(id: &str, uuid: &[u8], ip: &str) -> bool {
    // "(:test_hbbs:)" is the internal self-test peer, not a real machine
    if !registration_enabled() || id.is_empty() || uuid.is_empty() || id == "(:test_hbbs:)" {
        return true;
    }
    let uuid_b64 = base64::encode(uuid);
    let now = Instant::now();
    {
        let cache = REGISTER_CACHE.lock().await;
        if let Some((cached, tm)) = cache.get(id) {
            if *cached == uuid_b64
                && now.duration_since(*tm).as_secs() < CONFIG.register_cache_secs
            {
                return true;
            }
        }
    }
    match call_registro(id, &uuid_b64, ip).await {
        Ok(None) => {
            let mut cache = REGISTER_CACHE.lock().await;
            if cache.len() >= MAX_CACHE_ENTRIES && !cache.contains_key(id) {
                let ttl = CONFIG.register_cache_secs;
                cache.retain(|_, (_, tm)| now.duration_since(*tm).as_secs() < ttl);
            }
            cache.insert(id.to_owned(), (uuid_b64, now));
            true
        }
        Ok(Some(motivo)) => {
            log::warn!(
                "BR_SUPORTE: peers/registro id={} uuid={} ip={} CONFLITO ({}) -> {}",
                id,
                uuid_b64,
                ip,
                motivo,
                if CONFIG.register_enforce {
                    "UUID_MISMATCH (client sorteia outro ID)"
                } else {
                    "aceito, SÓ LOG (CONTROL_API_REGISTER_ENFORCE=N)"
                }
            );
            !CONFIG.register_enforce
        }
        Err(err) => {
            log::warn!(
                "BR_SUPORTE: peers/registro id={} FALHOU ({}) -> aceito (fail-open)",
                id,
                err
            );
            true
        }
    }
}

/// Ok(None) = aceito; Ok(Some(motivo)) = ID de outra máquina; Err = sem resposta útil.
async fn call_registro(id: &str, uuid_b64: &str, ip: &str) -> Result<Option<String>, String> {
    let client = HTTP_REGISTER
        .as_ref()
        .ok_or_else(|| "http client unavailable".to_owned())?;
    let mut req = client
        .post(format!("{}/peers/registro", CONFIG.url))
        .json(&with_server(serde_json::json!({ "id": id, "uuid": uuid_b64, "ip": ip })));
    if !CONFIG.token.is_empty() {
        req = req.bearer_auth(&CONFIG.token);
    }
    let started = Instant::now();
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    log::info!(
        "BR_SUPORTE: POST /peers/registro id={} -> HTTP {} em {}ms",
        id,
        status,
        started.elapsed().as_millis()
    );
    if status != 200 {
        return Err(format!("unexpected status {}", status));
    }
    let body = resp
        .json::<serde_json::Value>()
        .await
        .map_err(|e| format!("invalid json: {}", e))?;
    match body.get("ok").and_then(|v| v.as_bool()) {
        Some(true) => Ok(None),
        Some(false) => Ok(Some(
            body.get("motivo")
                .and_then(|m| m.as_str())
                .unwrap_or("?")
                .to_owned(),
        )),
        None => Err("missing \"ok\" in body".to_owned()),
    }
}

/// One connection attempt, as reported to the API audit endpoint.
pub struct Attempt<'a> {
    /// "punch_hole" or "relay"
    pub kind: &'a str,
    /// RustDesk id of the machine being connected to
    pub target_id: &'a str,
    pub from_ip: &'a str,
    /// controller session token, empty when the client was not logged in
    pub token: &'a str,
    /// user name as reported by /tokens/verify, when known
    pub user: Option<&'a str>,
    /// "allowed" or Denial::code()
    pub result: &'a str,
    /// user-facing refusal message, None when allowed
    pub reason: Option<&'a str>,
    /// ConnType enum name (DEFAULT_CONN, FILE_TRANSFER, ...)
    pub conn_type: &'a str,
    /// client version, only known on punch hole requests
    pub version: Option<&'a str>,
    /// "tcp" or "ws"
    pub via: &'a str,
}

/// Reports a connection attempt (allowed or blocked) to the control API.
///
/// Audit only: this NEVER blocks, delays or changes a connection. The request
/// runs in a detached task and every failure (timeout, 404, API down, no http
/// client) ends in a log line. Deduplicated by (ip, target, result) for
/// CONTROL_API_ATTEMPT_DEDUPE_SECS, because clients retry the punch hole
/// request several times and then ask for a relay for the same connection.
pub async fn report_attempt(a: Attempt<'_>) {
    if !is_enabled() || !CONFIG.attempts || a.target_id.is_empty() {
        return;
    }
    let now = Instant::now();
    let key = format!("{}|{}|{}", a.from_ip, a.target_id, a.result);
    {
        let mut sent = ATTEMPT_SENT.lock().await;
        if let Some(tm) = sent.get(&key) {
            if now.duration_since(*tm).as_secs() < CONFIG.attempt_dedupe_secs {
                log::debug!(
                    "BR_SUPORTE: connections/attempt {} suprimido pelo dedupe ({}s restantes)",
                    key,
                    CONFIG
                        .attempt_dedupe_secs
                        .saturating_sub(now.duration_since(*tm).as_secs())
                );
                return;
            }
        }
        if sent.len() >= MAX_CACHE_ENTRIES && !sent.contains_key(&key) {
            let ttl = CONFIG.attempt_dedupe_secs;
            sent.retain(|_, tm| now.duration_since(*tm).as_secs() < ttl);
        }
        sent.insert(key.clone(), now);
    }
    let body = with_server(serde_json::json!({
        "target_id": a.target_id,
        "ip": a.from_ip,
        "token": a.token,
        "user": a.user,
        "result": a.result,
        "reason": a.reason,
        "kind": a.kind,
        "conn_type": a.conn_type,
        "version": a.version,
        "via": a.via,
        "at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    }));
    log::info!(
        "BR_SUPORTE: connections/attempt enviando {} kind={} user={:?}",
        key,
        a.kind,
        a.user
    );
    tokio::spawn(async move {
        if let Some(client) = HTTP.as_ref() {
            let mut req = client
                .post(format!("{}/connections/attempt", CONFIG.url))
                .json(&body);
            if !CONFIG.token.is_empty() {
                req = req.bearer_auth(&CONFIG.token);
            }
            let started = Instant::now();
            match req.send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        log::info!(
                            "BR_SUPORTE: connections/attempt {} -> HTTP {} em {}ms",
                            key,
                            resp.status().as_u16(),
                            started.elapsed().as_millis()
                        );
                    } else {
                        log::warn!(
                            "BR_SUPORTE: connections/attempt {} returned {}",
                            key,
                            resp.status()
                        );
                    }
                }
                Err(err) => log::warn!("BR_SUPORTE: connections/attempt {} failed: {}", key, err),
            }
        }
    });
}

/// Records a blocked connection attempt for the local console diagnostics.
pub async fn record_block(from_ip: &str, target_id: &str, reason: &str) {
    log::warn!(
        "BR_SUPORTE: blocked connection from {} to {}: {}",
        from_ip,
        target_id,
        reason
    );
    let mut lock = BLOCKS.lock().await;
    if lock.len() >= MAX_BLOCK_ENTRIES {
        lock.remove(0);
    }
    lock.push(BlockEntry {
        tm: Instant::now(),
        from_ip: from_ip.to_owned(),
        target_id: target_id.to_owned(),
        reason: reason.to_owned(),
    });
}

/// Diagnostics for the local console ("control-api" command).
pub async fn diag() -> String {
    use std::fmt::Write as _;
    let mut res = String::new();
    let _ = writeln!(res, "enabled: {}", is_enabled());
    if !is_enabled() {
        return res;
    }
    let _ = writeln!(res, "url: {}", CONFIG.url);
    let _ = writeln!(res, "server_name: {:?}", CONFIG.server_name);
    let _ = writeln!(
        res,
        "jwt_kids: {:?} (leeway {}s)",
        CONFIG.jwt_keys.keys().collect::<Vec<_>>(),
        JWT_LEEWAY_SECS
    );
    let _ = writeln!(res, "fail_open: {}", CONFIG.fail_open);
    let _ = writeln!(
        res,
        "timeout_ms: {} cache_secs: {} seen_secs: {}",
        CONFIG.timeout_ms, CONFIG.cache_secs, CONFIG.seen_secs
    );
    let _ = writeln!(
        res,
        "attempts: {} attempt_dedupe_secs: {}",
        CONFIG.attempts, CONFIG.attempt_dedupe_secs
    );
    let _ = writeln!(
        res,
        "register: {} register_enforce: {} register_timeout_ms: {} register_cache_secs: {}",
        CONFIG.register,
        CONFIG.register_enforce,
        CONFIG.register_timeout_ms,
        CONFIG.register_cache_secs
    );
    {
        let cache = TOKEN_CACHE.lock().await;
        let _ = writeln!(res, "token cache: {} entries", cache.len());
        for (token, e) in cache.iter().take(20) {
            let prefix: String = token.chars().take(8).collect();
            let _ = writeln!(
                res,
                "  {}... authorized={} user={:?} age={}s",
                prefix,
                e.authorized,
                e.user,
                e.tm.elapsed().as_secs()
            );
        }
    }
    {
        let seen = SEEN_SENT.lock().await;
        let _ = writeln!(res, "seen throttle: {} ids", seen.len());
    }
    {
        let attempts = ATTEMPT_SENT.lock().await;
        let _ = writeln!(res, "attempt dedupe: {} chaves", attempts.len());
    }
    {
        let reg = REGISTER_CACHE.lock().await;
        let _ = writeln!(res, "register cache: {} ids", reg.len());
    }
    {
        let blocks = BLOCKS.lock().await;
        let _ = writeln!(res, "recent blocks: {}", blocks.len());
        for e in blocks.iter().rev().take(20) {
            let age = e.tm.elapsed();
            let event_system = std::time::SystemTime::now() - age;
            let event_iso = chrono::DateTime::<chrono::Utc>::from(event_system)
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            let _ = writeln!(
                res,
                "  {} {} -> {}: {}",
                event_iso, e.from_ip, e.target_id, e.reason
            );
        }
    }
    res
}
