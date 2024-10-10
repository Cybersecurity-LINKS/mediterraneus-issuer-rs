// SPDX-FileCopyrightText: 2024 Fondazione LINKS
//
// SPDX-License-Identifier: GPL-3.0-or-later

use actix_cors::Cors;
use actix_web::{http, middleware::Logger, web, App, HttpServer};
#[cfg(debug_assertions)]
use dotenv::dotenv;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Provider};
use ethers::signers::{LocalWallet, Signer};
use mediterraneus_issuer::handlers::{challenges_handler, credentials_handler};
use mediterraneus_issuer::repository::postgres_repo::init;
use mediterraneus_issuer::utils::configs::{
    DLTConfig, DatabaseConfig, HttpServerConfig, IssuerConfig, KeyStorageConfig,
};
use mediterraneus_issuer::utils::eth::SignerMiddlewareShort;
use mediterraneus_issuer::utils::iota::IotaState;
use std::sync::Arc;

use clap::Parser;

/// Issuer command line arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Issuer configuration
    #[command(flatten)]
    issuer_config: IssuerConfig,

    /// Configuration parameters for the DLT
    #[command(flatten)]
    dlt_config: DLTConfig,

    /// HTTP Server configuration
    #[command(flatten)]
    http_server_config: HttpServerConfig,

    /// Configuration section for the KeyStorage
    #[command(flatten)]
    key_storage_config: KeyStorageConfig,

    /// Database configuration args
    #[command(flatten)]
    database_config: DatabaseConfig,
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    #[cfg(debug_assertions)]
    dotenv().ok();
    env_logger::init();

    // Parse command line arguments
    let args = Args::parse();

    let address = args.http_server_config.host_address;
    let port = args.http_server_config.host_port;

    // Initialize database connection pool
    let db_pool = init(args.database_config).await?;

    // Initialize provider
    let rpc_provider = &args.dlt_config.rpc_provider;
    let chain_id = args.dlt_config.chain_id;

    // Transactions will be signed with the private key below
    let local_wallet = ((&args
        .issuer_config
        .issuer_private_key
        .value()))
        .parse::<LocalWallet>()?
        .with_chain_id(chain_id);
    let provider = Provider::<Http>::try_from(rpc_provider)?;

    let signer: Arc<SignerMiddlewareShort> =
        Arc::new(SignerMiddleware::new(provider, local_wallet));
    let signer_data: web::Data<Arc<SignerMiddlewareShort>> = web::Data::new(signer);

    // Initialize iota_state (client, did, etc.), create or load issuer's identity.
    let iota_state = IotaState::init(&db_pool, args.dlt_config, args.key_storage_config).await?;
    let iota_state_data = web::Data::new(iota_state);

    log::info!("Starting up on {}:{}", address, port);
    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin() // TODO: define who is allowed
            .allowed_methods(vec!["GET", "POST", "DELETE"])
            .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
            .allowed_header(http::header::CONTENT_TYPE)
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(db_pool.clone()))
            .app_data(signer_data.clone())
            .app_data(iota_state_data.clone())
            .app_data(args.issuer_config.identity_sc_address.clone())
            .service(
                web::scope("/api")
                    .configure(credentials_handler::scoped_config)
                    .configure(challenges_handler::scoped_config),
            )
            .wrap(cors)
            .wrap(Logger::default())
    })
    .bind((address, port))?
    .run()
    .await
    .map_err(anyhow::Error::from)
}
