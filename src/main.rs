use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use clap::{Parser, ValueEnum};
use rmcp::{
    ServiceExt,
    transport::{
        stdio,
        streamable_http_server::{
            StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
        },
    },
};
use sha2::{Digest, Sha256};
use ssh_mcp_rs::{config::Config, server::SshMcp};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use subtle::ConstantTimeEq;
use tower_http::limit::RequestBodyLimitLayer;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    #[arg(long, env = "SSH_MCP_CONFIG")]
    config: PathBuf,
    #[arg(long, value_enum, default_value_t = Transport::Stdio)]
    transport: Transport,
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: SocketAddr,
    /// Validate configuration and key permissions, then exit without connecting.
    #[arg(long)]
    check_config: bool,
}
#[derive(Clone, ValueEnum)]
enum Transport {
    Stdio,
    Http,
}

async fn authenticate(
    State(expected): State<Arc<[u8; 32]>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let actual: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    if !bool::from(actual.ct_eq(expected.as_ref())) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    // HTTP MCP is machine-to-machine. No browser origins are allowed.
    if request.headers().contains_key(header::ORIGIN) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(request).await)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.check_config {
        Config::load(&args.config)?;
        eprintln!("Configuration and private-key permissions: PASS");
        return Ok(());
    }
    let service = SshMcp::new(args.config.clone())?;
    match args.transport {
        Transport::Stdio => {
            service.serve(stdio()).await?.waiting().await?;
        }
        Transport::Http => {
            ensure!(
                args.bind.ip().is_loopback(),
                "HTTP must bind to loopback; expose only through an authenticated tunnel/reverse proxy"
            );
            let token = std::env::var("SSH_MCP_HTTP_TOKEN").context(
                "HTTP requires SSH_MCP_HTTP_TOKEN (32+ bytes); never pass it on the command line",
            )?;
            ensure!(token.len() >= 32, "HTTP token must be at least 32 bytes");
            let token_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
            let mut http_config = StreamableHttpServerConfig::default();
            http_config.legacy_session_mode = false;
            http_config.json_response = true;
            let http_service = StreamableHttpService::new(
                move || Ok(service.clone()),
                Arc::new(LocalSessionManager::default()),
                http_config,
            );
            let app = Router::new()
                .nest_service("/mcp", http_service)
                .layer(RequestBodyLimitLayer::new(24 * 1024 * 1024))
                .layer(middleware::from_fn_with_state(
                    Arc::new(token_hash),
                    authenticate,
                ))
                .route("/health", get(|| async { "ok\n" }));
            let listener = tokio::net::TcpListener::bind(args.bind).await?;
            eprintln!("ssh-mcp-rs listening on {} (authenticated /mcp)", args.bind);
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
        }
    }
    Ok(())
}
