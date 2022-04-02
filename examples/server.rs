use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use bytes::Bytes;
use futures::StreamExt;
use http::{Request, StatusCode};
use rustls::{Certificate, PrivateKey};
use structopt::StructOpt;
use tokio::{fs::File, io::AsyncReadExt};
use tracing::{debug, error, info, trace_span, warn};

use h3::{
    capsule::{AddressAssign, Capsule},
    quic::BidiStream,
    server::RequestStream,
};

#[derive(StructOpt, Debug)]
#[structopt(name = "server")]
struct Opt {
    #[structopt(
        short,
        long,
        default_value = "0.0.0.0:4433",
        help = "What address:port to listen for new connections"
    )]
    pub listen: SocketAddr,

    #[structopt(flatten)]
    pub certs: Certs,
}

#[derive(StructOpt, Debug)]
pub struct Certs {
    #[structopt(
        long,
        short,
        help = "Certificate for TLS. \
                If present, `--key` is mandatory. \
                If omitted, a selfsigned certificate will be generated."
    )]
    pub cert: Option<PathBuf>,

    #[structopt(long, short, help = "Private key for the certificate.")]
    pub key: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .init();

    let opt = Opt::from_args();

    let crypto = load_crypto(opt.certs).await?;
    let server_config = h3_quinn::quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let (endpoint, mut incoming) = h3_quinn::quinn::Endpoint::server(server_config, opt.listen)?;

    info!("Listening on {}", opt.listen);

    while let Some(new_conn) = incoming.next().await {
        trace_span!("New connection being attempted");

        tokio::spawn(async move {
            match new_conn.await {
                Ok(conn) => {
                    debug!("New connection now established");

                    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn))
                        .await
                        .unwrap();

                    while let Some((req, stream)) = h3_conn.accept().await.unwrap() {
                        debug!("New request: {:#?}", req);

                        tokio::spawn(async {
                            if let Err(e) = handle_request(req, stream).await {
                                error!("request failed: {}", e);
                            }
                        });
                    }
                }
                Err(err) => {
                    warn!("accepting connection failed: {:?}", err);
                }
            }
        });
    }

    endpoint.wait_idle().await;

    Ok(())
}

async fn handle_request<T>(
    req: Request<()>,
    mut stream: RequestStream<T, Bytes>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: BidiStream<Bytes>,
{
    let status = if req.uri().path().contains("..") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::OK
    };

    let resp = http::Response::builder().status(status).body(()).unwrap();

    match stream.send_response(resp).await {
        Ok(_) => {
            debug!("Response to connection successful");
        }
        Err(err) => {
            error!("Unable to send response to connection peer: {:?}", err);
        }
    }

    // let capsule = Capsule::AddressAssign(AddressAssign {
    //     ip_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)),
    //     ip_prefix_length: 32,
    // });
    // stream.send_capsule(capsule).await?;

    Ok(stream.finish().await?)
}

static ALPN: &[u8] = b"h3";

async fn load_crypto(opt: Certs) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
    let (cert, key) = match (opt.cert, opt.key) {
        (None, None) => build_certs(),
        (Some(cert_path), Some(ref key_path)) => {
            let mut cert_v = Vec::new();
            let mut key_v = Vec::new();

            let mut cert_f = File::open(cert_path).await?;
            let mut key_f = File::open(key_path).await?;

            cert_f.read_to_end(&mut cert_v).await?;
            key_f.read_to_end(&mut key_v).await?;
            (rustls::Certificate(cert_v), PrivateKey(key_v))
        }
        (_, _) => return Err("cert and key args are mutually dependant".into()),
    };

    let mut crypto = rustls::ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    crypto.max_early_data_size = u32::MAX;
    crypto.alpn_protocols = vec![ALPN.into()];

    Ok(crypto)
}

pub fn build_certs() -> (Certificate, PrivateKey) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = PrivateKey(cert.serialize_private_key_der());
    let cert = Certificate(cert.serialize_der().unwrap());
    (cert, key)
}
