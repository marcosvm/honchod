use encryption::encryption_client::EncryptionClient;
use encryption::DecryptRequest;
use encryption::EncryptRequest;
use tonic::transport::Certificate;
use tonic::transport::Channel;
use tonic::transport::ClientTlsConfig;

pub mod encryption {
    tonic::include_proto!("encryption");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ca =
        std::fs::read_to_string(std::env::var("HONCHOD_CA").unwrap_or("./etc/ca.pem".to_string()))?;

    let server = std::env::var("HONCHOD_SERVER_URL").unwrap_or("https://[::]:33441".to_string());

    let channel = Channel::from_shared(server)?
        .tls_config(ClientTlsConfig::new().ca_certificate(Certificate::from_pem(&ca)))?
        .connect()
        .await?;

    let mut client = EncryptionClient::new(channel);

    let request = tonic::Request::new(EncryptRequest {
        message: "encrypt this please".into(),
    });

    let response = client.encrypt(request).await?;

    println!("response={:?}", response);

    let request = tonic::Request::new(DecryptRequest {
        message: "decrypt this please".into(),
    });

    let response = client.decrypt(request).await?;

    println!("response={:?}", response);
    Ok(())
}
