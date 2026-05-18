use serde_json;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::io::Read;
use reqwest::header;
use chrono::{DateTime, Utc};


#[derive(Deserialize)]
struct SapcliPluginConnection {
    proto: String,
    ashost: String,
    port: String,
    client: String,
    #[serde(rename = "type")]
    conn_type: String,
    path: String,
    #[allow(unused)]
    sysnr: Option<String>,
    verify: bool,
    ssl_server_cert: Option<String>,
}

type SapcliPluginParameters = HashMap<String, String>;

#[derive(Deserialize)]
struct SapcliPluginRequest {
    connection: SapcliPluginConnection,
    #[allow(unused)]
    parameters: SapcliPluginParameters,
}

#[derive(Serialize, Deserialize)]
struct SapcliCookie {
    name: String,
    value: String,
    domain: Option<String>,
    path: Option<String>,
    expires: Option<String>,
    secure: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct SapcliCookiePluginContent     {
    #[serde(rename = "type")]
    plugin_type: String,
    cookies: Vec<SapcliCookie>,
}

#[derive(Serialize, Deserialize)]
struct SapcliCookiePluginResponse {
    message: String,
    expiration: String,
    content: SapcliCookiePluginContent,
}

async fn handle_request(request: SapcliPluginRequest) -> Result<SapcliCookiePluginResponse, Box<dyn std::error::Error>> {
    // 1. Build a client explicitly enforcing the Windows Native TLS (Schannel) stack
    let mut client_builder = reqwest::Client::builder()
        .tls_backend_native();
    
    if request.connection.verify {
        // If SSL verification is enabled, we can optionally add the server certificate
        if !request.connection.ssl_server_cert.is_none() {
            // Load the server certificate and add it to the client's root store
            // TODO: load the certificate from the provided path or string and add it to the client builder
            let cert = reqwest::Certificate::from_pem(request.connection.ssl_server_cert.unwrap().as_bytes())
                .expect("Failed to parse server certificate");
            client_builder = client_builder.add_root_certificate(cert);
        }
    } else {
        // If SSL verification is disabled, we can set the client to accept invalid certificates
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }

    if request.parameters.get("auth").is_some() {
        let mut headers = header::HeaderMap::new();
        let auth_param = request.parameters.get("auth").unwrap();
        let mut auth_value = header::HeaderValue::from_str(auth_param)
            .expect("Invalid auth header value");
        auth_value.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, auth_value.clone()); 
        client_builder = client_builder.default_headers(headers);
    }

    let client = client_builder
        .build()
        .expect("Could not create client with native TLS backend");

    let url = format!("{}://{}:{}{}?sap-client={}", request.connection.proto, request.connection.ashost, request.connection.port, request.connection.path, request.connection.client);

    let method = if request.connection.conn_type == "adt" {
        reqwest::Method::GET
    } else if request.connection.conn_type == "rest" {
        reqwest::Method::HEAD 
    } else {
        return Err("Unsupported connection type".into());
    };

    let response = client
        .request(method, url)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!("Request failed with status: {}", response.status()).into());
    }

    let cookies = response.cookies()
        .map(|cookie| SapcliCookie {
            name: cookie.name().to_string(),
            value: cookie.value().to_string(),
            domain: cookie.domain().map(|d| d.to_string()),
            path: cookie.path().map(|p| p.to_string()),
            expires: cookie.expires().map(|e| { let et: DateTime<Utc> = e.into(); et.to_rfc3339() }),
            secure: Some(cookie.secure()),
        }).collect::<Vec<SapcliCookie>>();

    let content = SapcliCookiePluginContent {
        plugin_type: "cookie".to_string(),
        cookies: cookies,
    };

    // TODO: Determine the actual expiration time based on the cookies or set a default expiration time
    // Now + 1 hour to ISO 8601
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let expiration = now + 3600; 
    let expiration: DateTime<Utc> = DateTime::from(std::time::UNIX_EPOCH + std::time::Duration::from_secs(expiration));

    let response = SapcliCookiePluginResponse {
        message: "Request handled successfully".to_string(),
        expiration: expiration.to_rfc3339(),
        content,
    };

    Ok(response)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read the request from stdin
    let mut buffer = String::new();
    std::io::stdin().read_to_string(&mut buffer)?;

    // Stderr is used for logging
    eprintln!("Received request: {}", buffer);

    let request: SapcliPluginRequest = serde_json::from_str(&buffer)?;
    let response = handle_request(request).await?;
    // Write the response to stdout
    let response_json = serde_json::to_string(&response)?;
    println!("{}", response_json);
    Ok(())
}