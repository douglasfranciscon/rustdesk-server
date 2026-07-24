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
const MAX_CACHE_ENTRIES: usize = 10_000;
const MAX_BLOCK_ENTRIES: usize = 100;

struct Config {
    url: String,
    token: String,
    fail_open: bool,
    timeout_ms: u64,
    cache_secs: u64,
    seen_secs: u64,
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
    };
    if config.url.is_empty() {
        log::info!("BR_SUPORTE: CONTROL_API_URL vazio, feature DESLIGADA (comportamento vanilla)");
    } else {
        log::info!(
            "BR_SUPORTE: LIGADO url={} fail_open={} timeout_ms={} cache_secs={} seen_secs={} auth_bearer={}",
            config.url,
            config.fail_open,
            config.timeout_ms,
            config.cache_secs,
            config.seen_secs,
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

static TOKEN_CACHE: Lazy<Mutex<HashMap<String, TokenEntry>>> = Lazy::new(Default::default);
static SEEN_SENT: Lazy<Mutex<HashMap<String, Instant>>> = Lazy::new(Default::default);
static BLOCKS: Lazy<Mutex<Vec<BlockEntry>>> = Lazy::new(Default::default);

#[inline]
pub fn is_enabled() -> bool {
    !CONFIG.url.is_empty()
}

/// Checks whether the given client token belongs to an authorized controller.
/// Returns Ok(user name if reported by the API) to allow, Err(user-facing
/// message) to deny.
pub async fn check_token(token: &str, ip: &str) -> Result<Option<String>, String> {
    if !is_enabled() {
        return Ok(None);
    }
    if token.is_empty() {
        // TODO(debug-teste): logs verbosos desta fase de teste; remover depois
        log::info!("BR_SUPORTE: check_token ip={} token VAZIO -> bloqueado (login necessário)", ip);
        return Err(MSG_LOGIN_REQUIRED.to_owned());
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
                    Err(MSG_DENIED.to_owned())
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
                Err(MSG_DENIED.to_owned())
            }
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
                Err(MSG_API_DOWN.to_owned())
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
        .json(&serde_json::json!({ "token": token, "ip": ip }));
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
                .json(&serde_json::json!({ "id": id, "ip": ip }));
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
    let _ = writeln!(res, "fail_open: {}", CONFIG.fail_open);
    let _ = writeln!(
        res,
        "timeout_ms: {} cache_secs: {} seen_secs: {}",
        CONFIG.timeout_ms, CONFIG.cache_secs, CONFIG.seen_secs
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
