// SPDX-FileCopyrightText: 2024 Fondazione LINKS
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result};
use deadpool_postgres::Pool;
use identity_iota::{
    iota::{IotaClientExt, IotaDID, IotaIdentityClientExt, NetworkName},
    prelude::IotaDocument,
    storage::{JwkDocumentExt, JwkMemStore, Storage},
    verification::{jws::JwsAlgorithm, MethodScope},
};
use identity_stronghold::StrongholdStorage;
use iota_sdk::{
    client::{
        api::GetAddressesOptions,
        node_api::indexer::query_parameters::QueryParameter,
        secret::{stronghold::StrongholdSecretManager, SecretManager},
        Client, Password,
    },
    crypto::keys::bip39::Mnemonic,
    types::block::{address::Bech32Address, output::AliasOutput},
};
use serde_json::{self};

use ethers::core::types::U256;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::{
    core::{Duration, FromJson, Object, Timestamp, Url},
    credential::{
        Credential, CredentialBuilder, DecodedJwtCredential, FailFast, Jwt,
        JwtCredentialValidationOptions, JwtCredentialValidator, Subject,
    },
    did::DID,
    storage::JwsSignatureOptions,
};
use serde_json::json;

use crate::dtos::identity_dtos::CredentialSubject;
use crate::repository::{models::IssuerIdentity, operations::IssuerIdentityExt};

use super::configs::{ConfigSecret, DLTConfig, KeyStorageConfig};

pub type MemStorage = Storage<StrongholdStorage, StrongholdStorage>;

pub struct IotaState {
    pub client: Client,
    pub key_storage: MemStorage,
    pub stronghold_storage: StrongholdStorage,
    pub issuer_identity: IssuerIdentity,
    pub issuer_document: IotaDocument,
    pub faucet_url: String,
}

impl IotaState {
    pub async fn init(
        db_pool: &Pool,
        dlt_configuration: DLTConfig,
        key_storage_config: KeyStorageConfig,
    ) -> Result<Self> {
        log::info!("Creating or recovering issuer state...");

        let pg_client = &db_pool.get().await?;

        let client = Client::builder()
            .with_node(&dlt_configuration.node_url)?
            .finish()
            .await?;

        // Create or load issuer's identity.
        let (key_storage, secret_manager) = create_or_recover_key_storage(
            key_storage_config.file_path,
            key_storage_config.password,
            key_storage_config.mnemonic,
        )
        .await?;

        let faucet_url = dlt_configuration.faucet_api_endpoint;

        // check if a did already exists
        let (issuer_identity, issuer_document) = match pg_client.get_identity_did().await {
            Ok(identity) => {
                let issuer_document = client.resolve_did(&IotaDID::parse(&identity.did)?).await?;
                (identity, issuer_document)
            }
            Err(_) => {
                log::info!("Creating new identity... ");

                // create a did with a verification method
                let (_, issuer_document, fragment) = create_did(
                    &client,
                    secret_manager.as_secret_manager(),
                    &key_storage,
                    &faucet_url,
                )
                .await?;
                // save the created identity
                let new_issuer_identity = IssuerIdentity {
                    did: issuer_document.id().to_string(),
                    fragment,
                };
                pg_client
                    .insert_identity_issuer(&new_issuer_identity)
                    .await?;
                (new_issuer_identity, issuer_document)
            }
        };

        let iota_state = IotaState {
            client,
            key_storage,
            stronghold_storage: secret_manager,
            issuer_identity,
            issuer_document,
            faucet_url,
        };
        Ok(iota_state)
    }
}

/// Creates a DID Document and publishes it in a new Alias Output.
///
/// Its functionality is equivalent to the "create DID" Iota example.
pub async fn create_did(
    client: &Client,
    secret_manager: &SecretManager,
    storage: &MemStorage,
    faucet_endpoint: &str,
) -> anyhow::Result<(Bech32Address, IotaDocument, String)> {
    let bech32_hrp = client.get_bech32_hrp().await?;
    let address = secret_manager
        .generate_ed25519_addresses(
            GetAddressesOptions::default()
                .with_range(0..1)
                .with_bech32_hrp(bech32_hrp),
        )
        .await?[0];
    ensure_address_has_funds(client, &address, faucet_endpoint).await?;

    let network_name: NetworkName = client.network_name().await?;
    let (document, fragment): (IotaDocument, String) =
        create_did_document(&network_name, storage).await?;
    let alias_output: AliasOutput = client
        .new_did_output(address.into_inner(), document, None)
        .await?;
    let document: IotaDocument = client
        .publish_did_output(secret_manager, alias_output)
        .await?;

    Ok((address, document, fragment))
}

/// Creates an example DID document with the given `network_name`.
///
/// Its functionality is equivalent to the "create DID" example
/// and exists for convenient calling from the other examples.
pub async fn create_did_document(
    network_name: &NetworkName,
    storage: &MemStorage,
) -> anyhow::Result<(IotaDocument, String)> {
    let mut document: IotaDocument = IotaDocument::new(network_name);

    let fragment: String = document
        .generate_method(
            storage,
            JwkMemStore::ED25519_KEY_TYPE,
            JwsAlgorithm::EdDSA,
            None,
            MethodScope::VerificationMethod,
        )
        .await?;

    Ok((document, fragment))
}

pub async fn create_or_recover_key_storage(
    snapshot_path: String,
    password: ConfigSecret,
    mnemonic: ConfigSecret,
) -> Result<(MemStorage, StrongholdStorage)> {
    log::info!("Creating or recovering storage...");

    // Setup Stronghold secret_manager
    let stronghold = StrongholdSecretManager::builder()
        .password(Password::from(password.value()))
        .build(snapshot_path)?;

    // Only required the first time, can also be generated with `manager.generate_mnemonic()?`
    let mnemonic = Mnemonic::from(mnemonic.value());

    match stronghold.store_mnemonic(mnemonic).await {
        Ok(()) => log::info!("Stronghold mnemonic stored"),
        Err(iota_sdk::client::stronghold::Error::MnemonicAlreadyStored) => {
            log::info!("Stronghold mnemonic already stored")
        }
        Err(error) => panic!("Error: {:?}", error),
    }

    // Create a `StrongholdStorage`.
    // `StrongholdStorage` creates internally a `SecretManager` that can be
    // referenced to avoid creating multiple instances around the same stronghold snapshot.
    let stronghold_storage = StrongholdStorage::new(stronghold);

    // Create storage for key-ids and JWKs.
    //
    // In this example, the same stronghold file that is used to store
    // key-ids as well as the JWKs.
    let key_storage = Storage::new(stronghold_storage.clone(), stronghold_storage.clone());

    Ok((key_storage, stronghold_storage))
}

/// Requests funds from the faucet for the given `address`.
pub async fn request_faucet_funds(
    client: &Client,
    address: &Bech32Address,
    faucet_endpoint: &str,
) -> anyhow::Result<()> {
    iota_sdk::client::request_funds_from_faucet(faucet_endpoint, &address).await?;

    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            let balance = get_address_balance(client, &address)
                .await
                .context("failed to get address balance")?;
            if balance > 0 {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("maximum timeout exceeded")??;

    Ok(())
}

/// Returns the balance of the given Bech32-encoded `address`.
pub async fn get_address_balance(client: &Client, address: &Bech32Address) -> anyhow::Result<u64> {
    let output_ids = client
        .basic_output_ids(vec![
            QueryParameter::Address(address.to_owned()),
            QueryParameter::HasExpiration(false),
            QueryParameter::HasTimelock(false),
            QueryParameter::HasStorageDepositReturn(false),
        ])
        .await?;

    let outputs = client.get_outputs(&output_ids).await?;

    let mut total_amount = 0;
    for output_response in outputs {
        total_amount += output_response.output().amount();
    }

    Ok(total_amount)
}

pub async fn ensure_address_has_funds(
    client: &Client,
    address: &Bech32Address,
    faucet_endpoint: &str,
) -> anyhow::Result<()> {
    let balance = get_address_balance(client, address)
        .await
        .context("failed to get address balance")?;

    if balance == 0 {
        log::info!("Funding address {}", address);
        request_faucet_funds(client, address, faucet_endpoint).await?;
    } else {
        log::info!("Address has already enough funds: {}.", balance);
    }
    Ok(())
}

pub async fn create_credential(
    holder_document: &IotaDocument,
    issuer_document: &IotaDocument,
    vc_id: U256,
    storage_issuer: &MemStorage,
    fragment_issuer: &String,
    credential_subject: CredentialSubject,
) -> Result<(Jwt, DecodedJwtCredential)> {
    // Create a credential subject // TODO: fill this from user request
    let subject: Subject = Subject::from_json_value(json!({
        "id": holder_document.id().as_str(),
        "name": credential_subject.name,
        "surname": credential_subject.surname,
        "userOf": "SEDIMARK marketplace"
    }))?;

    // Build credential using subject above and issuer.
    let credential_base_url = "https://example.market/credentials/"; //TODO: define a uri

    let credential: Credential = CredentialBuilder::default()
        .id(Url::parse(format!("{}{}", credential_base_url, vc_id))?)
        .issuer(Url::parse(issuer_document.id().as_str())?)
        .type_("MarketplaceCredential") // TODO: define a type somewhere else
        .expiration_date(
            Timestamp::now_utc()
                .checked_add(Duration::days(365))
                .unwrap(),
        ) // TODO: define this as a parameter
        .issuance_date(Timestamp::now_utc().checked_sub(Duration::days(1)).unwrap()) //TODO: this solved an error with the eth node time
        .subject(subject)
        .build()?;

    // Sign the credential
    let credential_jwt: Jwt = issuer_document
        .create_credential_jwt(
            &credential,
            &storage_issuer,
            &fragment_issuer,
            &JwsSignatureOptions::default(),
            None,
        )
        .await?;

    // To ensure the credential's validity, the issuer must validate it before issuing it to the holder

    // Validate the credential's signature using the issuer's DID Document, the credential's semantic structure,
    // that the issuance date is not in the future and that the expiration date is not in the past:
    let decoded_credential: DecodedJwtCredential<Object> =
        JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default())
            .validate::<_, Object>(
                &credential_jwt,
                &issuer_document,
                &JwtCredentialValidationOptions::default(),
                FailFast::FirstError,
            )?;

    Ok((credential_jwt, decoded_credential))
}
