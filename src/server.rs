use tonic::transport::Identity;
use tonic::transport::Server;
use tonic::transport::ServerTlsConfig;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use encryption::encryption_server::Encryption;
use encryption::encryption_server::EncryptionServer;
use encryption::DecryptRequest;
use encryption::DecryptResponse;
use encryption::EncryptRequest;
use encryption::EncryptResponse;

pub mod encryption {
    tonic::include_proto!("encryption");
}

#[derive(Debug, Default)]
pub struct HostEncryption {}

#[tonic::async_trait]
impl Encryption for HostEncryption {
    async fn encrypt(
        &self,
        request: Request<EncryptRequest>,
    ) -> Result<Response<EncryptResponse>, Status> {
        println!("Got a request: {:?}", request);

        let reply = encryption::EncryptResponse {
            message: format!(
                "this is totally encrypted for {}",
                request.into_inner().message
            )
            .into(),
        };
        Ok(Response::new(reply))
    }
    async fn decrypt(
        &self,
        request: Request<DecryptRequest>,
    ) -> Result<Response<DecryptResponse>, Status> {
        println!("Got a request: {:?}", request);

        let reply = encryption::DecryptResponse {
            message: format!(
                "this is totally decrypted for {}",
                request.into_inner().message
            )
            .into(),
        };
        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::var("RANCHOD_BIND_ADDRESS")
        .unwrap_or("[::]:33441".to_string())
        .parse()?;

    let cert = std::fs::read_to_string(
        std::env::var("HONCHOD_SERVER_CERTIFICATE").unwrap_or("./etc/server.pem".to_string()),
    )?;

    let key = std::fs::read_to_string(
        std::env::var("HONCHOD_SERVER_CERTIFICATE_KEY")
            .unwrap_or("./etc/server-key.pem".to_string()),
    )?;

    let encryption_service = HostEncryption::default();
    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(Identity::from_pem(&cert, &key)))?
        .add_service(EncryptionServer::new(encryption_service))
        .serve(addr)
        .await?;

    Ok(())
}
