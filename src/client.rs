use encryption::encryption_client::EncryptionClient;
use encryption::DecryptRequest;
use encryption::EncryptRequest;

pub mod encryption {
    tonic::include_proto!("encryption");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = EncryptionClient::connect("http://[::1]:33441").await?;

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
