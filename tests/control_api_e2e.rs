// End-to-end tests for the control-api gate: spawns the real hbbs binary and
// the mock control API (tests/mock_api.py, requires python on PATH), then
// drives PunchHoleRequest/RequestRelay over TCP like a client would.
use hbb_common::{
    protobuf::Message as _,
    rendezvous_proto::*,
    tcp::FramedStream,
    tokio,
};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const TARGET_ID: &str = "999888777";

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.kill().ok();
        self.0.wait().ok();
    }
}

fn wait_tcp(port: u16) {
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("port {port} not ready");
}

fn spawn_mock(port: u16) -> Guard {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/mock_api.py");
    let child = Command::new("python")
        .arg(script)
        .arg(port.to_string())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn python mock");
    let guard = Guard(child);
    wait_tcp(port);
    guard
}

fn spawn_hbbs(port: u16, api_url: Option<&str>) -> Guard {
    spawn_hbbs_env(port, api_url, &[])
}

fn spawn_hbbs_env(port: u16, api_url: Option<&str>, extra_env: &[(&str, &str)]) -> Guard {
    let dir = std::env::temp_dir().join(format!("hbbs_e2e_{port}"));
    std::fs::create_dir_all(&dir).expect("create hbbs work dir");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hbbs"));
    cmd.current_dir(&dir)
        .env("PORT", port.to_string())
        // KEY vazio: hbbs não exige licence_key (o gate em teste é só o da control API)
        .env("KEY", "")
        .env_remove("CONTROL_API_URL")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(url) = api_url {
        cmd.env("CONTROL_API_URL", url)
            // nome deste hbbs nos envios à API (vai em minúsculas, como `server`)
            .env("CONTROL_API_SERVER_NAME", " HBBS-Teste.LOCAL ");
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let child = cmd.spawn().expect("spawn hbbs");
    let guard = Guard(child);
    wait_tcp(port);
    guard
}

/// Raw HTTP/1.0 GET of the mock's /_state (the test crate has no http client).
fn mock_state(port: u16) -> String {
    use std::io::{Read as _, Write as _};
    let mut stream =
        std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect to mock api");
    stream
        .write_all(b"GET /_state HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        .expect("send /_state request");
    let mut body = String::new();
    stream.read_to_string(&mut body).expect("read /_state");
    body
}

/// The attempt events are posted from a detached task, so poll for them.
fn wait_for_attempt(port: u16, needle: &str) -> String {
    for _ in 0..40 {
        let state = mock_state(port);
        if state.contains(needle) {
            return state;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("attempt {needle} never reached the mock api:\n{}", mock_state(port));
}

async fn connect(port: u16) -> FramedStream {
    FramedStream::new(format!("127.0.0.1:{port}"), None, 3000)
        .await
        .expect("connect to hbbs")
}

async fn punch(port: u16, token: &str) -> PunchHoleResponse {
    punch_to(port, token, TARGET_ID).await
}

async fn punch_to(port: u16, token: &str, target: &str) -> PunchHoleResponse {
    let mut stream = connect(port).await;
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: target.to_owned(),
        token: token.to_owned(),
        ..Default::default()
    });
    stream.send(&msg).await.expect("send punch hole request");
    let bytes = stream
        .next_timeout(5000)
        .await
        .expect("no response to punch hole request")
        .expect("read response");
    let resp = RendezvousMessage::parse_from_bytes(&bytes).expect("parse response");
    match resp.union {
        Some(rendezvous_message::Union::PunchHoleResponse(phr)) => phr,
        other => panic!("unexpected response: {other:?}"),
    }
}

async fn request_relay(port: u16, token: &str) -> Option<RelayResponse> {
    let mut stream = connect(port).await;
    let mut msg = RendezvousMessage::new();
    msg.set_request_relay(RequestRelay {
        id: TARGET_ID.to_owned(),
        token: token.to_owned(),
        ..Default::default()
    });
    stream.send(&msg).await.expect("send request relay");
    let bytes = stream.next_timeout(1500).await?.expect("read response");
    let resp = RendezvousMessage::parse_from_bytes(&bytes).expect("parse response");
    match resp.union {
        Some(rendezvous_message::Union::RelayResponse(rr)) => Some(rr),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn gate_blocks_and_allows_by_token() {
    let mock = spawn_mock(41999);
    let _hbbs = spawn_hbbs(41116, Some("http://127.0.0.1:41999"));

    // Sem login (token vazio): bloqueado com mensagem pedindo login.
    let resp = punch(41116, "").await;
    assert!(
        resp.other_failure.contains("login"),
        "expected login-required message, got: {resp:?}"
    );

    // Token desconhecido: bloqueado como não autorizado.
    let resp = punch(41116, "tok-invalido").await;
    assert!(
        resp.other_failure.contains("não autorizado"),
        "expected denied message, got: {resp:?}"
    );

    // Token aprovado: passa pelo gate e cai na checagem normal de peer
    // (o alvo não existe, então ID_NOT_EXIST prova que o gate liberou).
    let resp = punch(41116, "tok-aprovado").await;
    assert!(resp.other_failure.is_empty(), "gate should not block: {resp:?}");
    assert_eq!(
        resp.failure.enum_value_or_default(),
        punch_hole_response::Failure::ID_NOT_EXIST,
        "expected ID_NOT_EXIST after passing the gate: {resp:?}"
    );

    // RequestRelay com token inválido: recusado com refuse_reason.
    let rr = request_relay(41116, "tok-invalido2")
        .await
        .expect("expected a relay refusal response");
    assert!(
        !rr.refuse_reason.is_empty(),
        "expected refuse_reason, got: {rr:?}"
    );

    // RequestRelay com token aprovado: gate libera; como o peer alvo não
    // existe, nada é encaminhado e não chega resposta (sem recusa).
    let rr = request_relay(41116, "tok-aprovado").await;
    assert!(rr.is_none(), "approved relay must not be refused: {rr:?}");

    // Toda tentativa acima virou evento de auditoria na API, com o desfecho.
    let state = wait_for_attempt(41999, r#""result": "allowed""#);
    assert!(
        state.contains(r#""result": "login_required""#),
        "expected a login_required attempt event: {state}"
    );
    assert!(
        state.contains(r#""result": "denied""#),
        "expected a denied attempt event: {state}"
    );
    assert!(
        state.contains(&format!(r#""target_id": "{TARGET_ID}""#)),
        "attempt events must carry the target id: {state}"
    );
    assert!(
        state.contains(r#""kind": "punch_hole""#),
        "expected punch_hole events: {state}"
    );
    // CONTROL_API_SERVER_NAME chega como `server`, aparado e em minúsculas, nos
    // eventos de tentativa e no peers/seen (distingue os hbbs redundantes).
    assert!(
        state.contains(r#""server": "hbbs-teste.local""#),
        "attempt events must carry the server name: {state}"
    );
    assert!(
        !state.contains("HBBS-Teste"),
        "server name must be lowercased: {state}"
    );
    // Os RequestRelay acima repetem (ip, alvo, desfecho) dos punch holes, então
    // o dedupe os suprime: 1 evento por conexão, não um por pacote.
    assert!(
        !state.contains(r#""kind": "relay""#),
        "relay attempts duplicating a punch hole must be deduped: {state}"
    );

    // API fora do ar + token não cacheado: fail-closed (default) bloqueia.
    drop(mock);
    let resp = punch(41116, "tok-novo-sem-cache").await;
    assert!(
        resp.other_failure.contains("indisponível"),
        "expected fail-closed message, got: {resp:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn attempt_post_failure_does_not_block() {
    let mock = spawn_mock(43999);
    let _hbbs = spawn_hbbs(43116, Some("http://127.0.0.1:43999"));

    // Primeiro punch coloca o token no cache do hbbs (60s).
    let resp = punch(43116, "tok-aprovado").await;
    assert!(resp.other_failure.is_empty(), "gate should not block: {resp:?}");

    // API some. O token segue valendo pelo cache, mas o POST de auditoria vai
    // falhar — e isso não pode alterar em nada a resposta da conexão. Alvo
    // diferente para não cair no dedupe e garantir que o POST é tentado.
    drop(mock);
    let started = std::time::Instant::now();
    let resp = punch_to(43116, "tok-aprovado", "111222333").await;
    assert!(
        resp.other_failure.is_empty(),
        "a failing audit post must not refuse the connection: {resp:?}"
    );
    assert_eq!(
        resp.failure.enum_value_or_default(),
        punch_hole_response::Failure::ID_NOT_EXIST,
        "expected the normal ID_NOT_EXIST: {resp:?}"
    );
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "the audit post must not be awaited on the connection path (took {:?})",
        started.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn vanilla_without_api_url_does_not_block() {
    let _hbbs = spawn_hbbs(42116, None);

    // Sem CONTROL_API_URL o gate fica desligado: comportamento original.
    let resp = punch(42116, "").await;
    assert!(resp.other_failure.is_empty(), "vanilla must not block: {resp:?}");
    assert_eq!(
        resp.failure.enum_value_or_default(),
        punch_hole_response::Failure::ID_NOT_EXIST,
        "expected plain ID_NOT_EXIST: {resp:?}"
    );
}

/// Chave Ed25519 de TESTE (gerada a cada execução) no formato que a API publica:
/// a linha do meio do PEM "PUBLIC KEY" (SPKI em base64). Nunca a chave de produção.
fn gen_test_keypair() -> (String, sodiumoxide::crypto::sign::SecretKey) {
    use sodiumoxide::crypto::sign;
    sodiumoxide::init().ok();
    let (pk, sk) = sign::gen_keypair();
    // SubjectPublicKeyInfo de Ed25519 (RFC 8410): prefixo fixo + 32 bytes da chave.
    let mut spki = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki.extend_from_slice(pk.as_ref());
    (base64::encode(spki), sk)
}

/// Monta um JWT EdDSA como a API faz: header {alg, typ, kid}, payload, assinatura
/// Ed25519 sobre "header.payload", tudo em base64url sem padding.
fn make_jwt(kid: &str, sk: &sodiumoxide::crypto::sign::SecretKey, exp: i64, name: &str) -> String {
    use sodiumoxide::crypto::sign;
    let b64 = |b: &[u8]| base64::encode_config(b, base64::URL_SAFE_NO_PAD);
    let header = b64(format!(r#"{{"alg":"EdDSA","typ":"JWT","kid":"{kid}"}}"#).as_bytes());
    let now = chrono::Utc::now().timestamp();
    let payload = b64(
        format!(
            r#"{{"sid":"{}","sub":"8","pc":"123456789","name":"{name}","iat":{now},"exp":{exp}}}"#,
            "a".repeat(64)
        )
        .as_bytes(),
    );
    let signing_input = format!("{header}.{payload}");
    let sig = sign::sign_detached(signing_input.as_bytes(), sk);
    format!("{signing_input}.{}", b64(sig.as_ref()))
}

#[tokio::test(flavor = "multi_thread")]
async fn jwt_offline_only_when_api_is_down() {
    let (pub_b64, sk) = gen_test_keypair();
    let (_other_pub, other_sk) = gen_test_keypair();
    let keys = format!("k1={pub_b64}");
    let mock = spawn_mock(44999);
    let _hbbs = spawn_hbbs_env(
        44116,
        Some("http://127.0.0.1:44999"),
        &[("CONTROL_API_JWT_KEYS", keys.as_str())],
    );
    let in_1h = chrono::Utc::now().timestamp() + 3600;

    // Com a API de pé, quem decide é ela: JWT válido mas não aprovado na API -> negado.
    let jwt_nao_aprovado = make_jwt("k1", &sk, in_1h, "fulano");
    let resp = punch(44116, &jwt_nao_aprovado).await;
    assert!(
        resp.other_failure.contains("não autorizado"),
        "with the API up a JWT must not bypass it: {resp:?}"
    );

    // API fora do ar (tokens novos, sem cache):
    drop(mock);

    // JWT válido, assinado pela chave conhecida -> liberado offline.
    let jwt_ok = make_jwt("k1", &sk, in_1h, "beltrano");
    let resp = punch(44116, &jwt_ok).await;
    assert!(
        resp.other_failure.is_empty(),
        "valid JWT must be accepted offline: {resp:?}"
    );
    // ...e via relay também (mesmo check_token).
    let rr = request_relay(44116, &jwt_ok).await;
    assert!(rr.is_none(), "valid JWT must not be refused on relay: {rr:?}");

    // JWT vencido (além da folga de 60 s) -> bloqueado com mensagem de sessão expirada.
    let jwt_vencido = make_jwt("k1", &sk, chrono::Utc::now().timestamp() - 3600, "beltrano");
    let resp = punch(44116, &jwt_vencido).await;
    assert!(
        resp.other_failure.contains("expirou"),
        "expired JWT must be refused offline: {resp:?}"
    );

    // JWT assinado por outra chave (kid conhecido, assinatura errada) -> bloqueado.
    let jwt_forjado = make_jwt("k1", &other_sk, in_1h, "intruso");
    let resp = punch(44116, &jwt_forjado).await;
    assert!(
        resp.other_failure.contains("indisponível"),
        "forged JWT must be refused offline: {resp:?}"
    );

    // kid desconhecido -> bloqueado.
    let jwt_kid = make_jwt("k9", &sk, in_1h, "beltrano");
    let resp = punch(44116, &jwt_kid).await;
    assert!(
        resp.other_failure.contains("indisponível"),
        "unknown kid must be refused offline: {resp:?}"
    );

    // Token opaco antigo com a API fora: comportamento de sempre (fail-closed).
    let resp = punch(44116, "tok-opaco-antigo").await;
    assert!(
        resp.other_failure.contains("indisponível"),
        "opaque token must keep the fail-closed behavior: {resp:?}"
    );
}
