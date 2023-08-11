use std::env;
use std::sync::Arc;
use mediterraneus_issuer::{IssuerState, EthClient, LocalContractInstance};
use mediterraneus_issuer::services::issuer_wallet::setup_eth_wallet;
use mediterraneus_issuer::services::{issuer_wallet, issuer_identity};
use mediterraneus_issuer::config::config;
use mediterraneus_issuer::handler::issuer_handler;
use mediterraneus_issuer::utils::{setup_client, ensure_address_has_funds};
use tokio_postgres::NoTls;
use actix_web::{web, App, HttpServer, middleware::Logger, http};
use actix_cors::Cors;
use ethers::providers::{Provider, Http};
use ethers::middleware::SignerMiddleware;
use ethers::signers::{LocalWallet, Signer};

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init();

    let config = config::get_db_config();
    let pool = config.create_pool(None, NoTls).unwrap();

    let address = env::var("ADDR").expect("$ADDR must be set.");
    let port = env::var("PORT").expect("$PORT must be set.").parse::<u16>().unwrap();

    // first create or load issuer's identity.
    let client = setup_client();
    let faucet_endpoint = env::var("FAUCET_URL").expect("$FAUCET_URL must be set");

    let (account_manager, account) = issuer_wallet::create_or_load_wallet_account().await?;
    let wallet_address = account.addresses().await?[0].address().clone();

    ensure_address_has_funds(&client.clone(), wallet_address.as_ref().clone(), &faucet_endpoint.clone()).await?;
    
    let secret_manager = account_manager.get_secret_manager();
    let issuer_identity = issuer_identity::create_identity(
        &client.clone(), wallet_address.as_ref().clone(), &mut *secret_manager.write().await, pool.clone())
        .await?;

    let provider = Provider::<Http>::try_from(env::var("SHIMMER_JSON_RPC_URL")
    .expect("$SHIMMER_JSON_RPC_URL must be set"))?;
    // Transactions will be signed with the private key below
    let eth_wallet: LocalWallet = env::var("PRIVATE_KEY")
        .expect("$PRIVATE_KEY must be set")
        .parse::<LocalWallet>()?
        .with_chain_id(1072u64);
    let eth_client: Arc<EthClient> = Arc::new(SignerMiddleware::new(provider, eth_wallet.clone()));

    let idsc_instance: LocalContractInstance = setup_eth_wallet(eth_client.clone()).await;

    log::info!("Starting up on {}:{}", address, port);
    HttpServer::new(move || {
        let cors = Cors::default()
        .allow_any_origin() 
        .allowed_methods(vec!["GET", "POST"])
        .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
        .allowed_header(http::header::CONTENT_TYPE)
        .max_age(3600);

        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(
                IssuerState {
                    issuer_account: account.clone(),
                    secret_manager: secret_manager.clone(),
                    issuer_identity: issuer_identity.clone(),
                    eth_client: eth_client.clone(),
                    idsc_instance: idsc_instance.clone()
                })
            )
            .service(web::scope("/api")
                .configure(issuer_handler::scoped_config)
            )
            .wrap(cors)
            .wrap(Logger::default())
    })
    .bind((address, port))?
    .run()
    .await.map_err(anyhow::Error::from)
}
