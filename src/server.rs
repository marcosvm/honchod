use tonic::transport::Server;
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
    let addr = "[::1]:33441".parse()?;
    let encryption = HostEncryption::default();

    Server::builder()
        .add_service(EncryptionServer::new(encryption))
        .serve(addr)
        .await?;

    Ok(())
}
