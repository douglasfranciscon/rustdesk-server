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
        cmd.env("CONTROL_API_URL", url);
    }
    let child = cmd.spawn().expect("spawn hbbs");
    let guard = Guard(child);
    wait_tcp(port);
    guard
}

async fn connect(port: u16) -> FramedStream {
    FramedStream::new(format!("127.0.0.1:{port}"), None, 3000)
        .await
        .expect("connect to hbbs")
}

async fn punch(port: u16, token: &str) -> PunchHoleResponse {
    let mut stream = connect(port).await;
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: TARGET_ID.to_owned(),
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

    // API fora do ar + token não cacheado: fail-closed (default) bloqueia.
    drop(mock);
    let resp = punch(41116, "tok-novo-sem-cache").await;
    assert!(
        resp.other_failure.contains("indisponível"),
        "expected fail-closed message, got: {resp:?}"
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
