use crate::config::{AgentControllerConfig, ControllerNetworkConfig};
use crate::controller::Controller;
use crate::model::{Job, NodeResult};
use crate::util::{canonical_json, sha256_hex};
use crate::{Error, Result};
use rustls::client::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{ServerConfig, WebPkiClientVerifier};
use rustls::{ClientConnection, RootCertStore, ServerConnection, StreamOwned};
use rustls_pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::thread;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentRequest {
    Ping { node_id: String },
    Claim { node_id: String },
    Complete { node_id: String, result: NodeResult },
}

impl AgentRequest {
    fn node_id(&self) -> &str {
        match self {
            Self::Ping { node_id } | Self::Claim { node_id } | Self::Complete { node_id, .. } => {
                node_id
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControllerResponse {
    Pong { server_time: String },
    NoJob { retry_after_seconds: u64 },
    Job { job: Job },
    Accepted,
    Error { code: String, message: String },
}

pub fn serve(controller: Controller) -> Result<()> {
    let address = controller.config.network.bind.clone();
    let tls = Arc::new(server_tls_config(&controller.config.network)?);
    let listener = TcpListener::bind(&address)?;
    let controller = Arc::new(controller);
    for connection in listener.incoming() {
        match connection {
            Ok(socket) => {
                let controller = Arc::clone(&controller);
                let tls = Arc::clone(&tls);
                thread::spawn(move || {
                    let _ = handle_connection(socket, controller.as_ref(), tls);
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Error::Io(error)),
        }
    }
    Ok(())
}

fn handle_connection(
    socket: TcpStream,
    controller: &Controller,
    tls: Arc<ServerConfig>,
) -> Result<()> {
    socket.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    socket.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
    let connection =
        ServerConnection::new(tls).map_err(|error| Error::Protocol(error.to_string()))?;
    let mut stream = StreamOwned::new(connection, socket);
    let request: AgentRequest = read_frame(&mut stream, controller.config.network.max_frame_bytes)?;
    let certificate = stream
        .conn
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .ok_or_else(|| Error::Authentication("agent did not present a certificate".into()))?;
    let actual = sha256_hex(certificate.as_ref());
    let expected = controller.expected_certificate_fingerprint(request.node_id())?;
    if actual != expected {
        return Err(Error::Authentication(
            "agent certificate fingerprint does not match enrollment".into(),
        ));
    }
    let response = match request {
        AgentRequest::Ping { .. } => ControllerResponse::Pong {
            server_time: crate::util::now().to_rfc3339(),
        },
        AgentRequest::Claim { node_id } => match controller.claim(&node_id)? {
            Some(job) => ControllerResponse::Job { job },
            None => ControllerResponse::NoJob {
                retry_after_seconds: controller.config.network.lease_seconds.min(30),
            },
        },
        AgentRequest::Complete { node_id, result } => {
            controller.complete(&node_id, &result)?;
            ControllerResponse::Accepted
        }
    };
    write_frame(
        &mut stream,
        &response,
        controller.config.network.max_frame_bytes,
    )?;
    stream.flush()?;
    Ok(())
}

pub struct AgentClient {
    config: AgentControllerConfig,
    tls: Arc<ClientConfig>,
}

impl AgentClient {
    pub fn new(config: AgentControllerConfig) -> Result<Self> {
        let tls = Arc::new(client_tls_config(&config)?);
        Ok(Self { config, tls })
    }

    pub fn request(&self, request: &AgentRequest) -> Result<ControllerResponse> {
        let socket = TcpStream::connect(&self.config.address)?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
        socket.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
        let server_name = ServerName::try_from(self.config.server_name.clone())
            .map_err(|_| Error::InvalidInput("invalid TLS server name".into()))?;
        let connection = ClientConnection::new(Arc::clone(&self.tls), server_name)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        let mut stream = StreamOwned::new(connection, socket);
        write_frame(&mut stream, request, self.config.max_frame_bytes)?;
        stream.flush()?;
        read_frame(&mut stream, self.config.max_frame_bytes)
    }
}

fn server_tls_config(config: &ControllerNetworkConfig) -> Result<ServerConfig> {
    let mut roots = RootCertStore::empty();
    for certificate in load_certificates(&config.client_ca)? {
        roots
            .add(certificate)
            .map_err(|error| Error::Crypto(error.to_string()))?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|error| Error::Crypto(error.to_string()))?;
    ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            load_certificates(&config.tls_certificate)?,
            load_private_key(&config.tls_private_key)?,
        )
        .map_err(|error| Error::Crypto(error.to_string()))
}

fn client_tls_config(config: &AgentControllerConfig) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for certificate in load_certificates(&config.ca_certificate)? {
        roots
            .add(certificate)
            .map_err(|error| Error::Crypto(error.to_string()))?;
    }
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            load_certificates(&config.client_certificate)?,
            load_private_key(&config.client_private_key)?,
        )
        .map_err(|error| Error::Crypto(error.to_string()))
}

fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certificates = CertificateDer::pem_file_iter(path)
        .map_err(|error| Error::Crypto(error.to_string()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| Error::Crypto(error.to_string()))?;
    if certificates.is_empty() {
        return Err(Error::Crypto(format!(
            "{} contains no certificates",
            path.display()
        )));
    }
    Ok(certificates)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path).map_err(|error| Error::Crypto(error.to_string()))
}

fn read_frame<T: for<'de> Deserialize<'de>>(reader: &mut impl Read, max_bytes: usize) -> Result<T> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| Error::Protocol("invalid frame length".into()))?;
    if length == 0 || length > max_bytes {
        return Err(Error::Protocol(format!(
            "frame length {length} exceeds configured limit"
        )));
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload)?;
    Ok(serde_json::from_slice(&payload)?)
}

fn write_frame<T: Serialize>(writer: &mut impl Write, value: &T, max_bytes: usize) -> Result<()> {
    let payload = canonical_json(value)?;
    if payload.is_empty() || payload.len() > max_bytes || payload.len() > u32::MAX as usize {
        return Err(Error::Protocol(format!(
            "outbound frame length {} exceeds configured limit",
            payload.len()
        )));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| Error::Protocol("frame length cannot be represented".into()))?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&payload)?;
    Ok(())
}
