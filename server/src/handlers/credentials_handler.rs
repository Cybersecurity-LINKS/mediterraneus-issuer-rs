// SPDX-FileCopyrightText: 2024 Fondazione LINKS
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::str::FromStr;
use std::sync::Arc;

use actix_web::{web, HttpResponse, Responder, post, delete};
use deadpool_postgres::Pool;

use ethers::abi::RawLog;
use ethers::contract::EthEvent;
use ethers::core::types::U256;
use ethers::types::{Address, Signature};

use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::credential::Jws;
use identity_iota::document::verifiable::JwsVerificationOptions;
use identity_iota::iota::{IotaDID, IotaIdentityClientExt};

use crate::contracts::identity::{Identity, VcRevokedFilter};
use crate::dtos::identity_dtos::{CredentialRequestDTO, CredentialIssuedResponse};
use crate::errors::IssuerError;
use crate::repository::operations::HoldersChallengesExt;
use crate::utils::eth::{update_identity_sc, SignerMiddlewareShort};
use crate::utils::iota::{create_credential, IotaState};

// use actix_web_lab::middleware::from_fn;
// use crate::middlewares::ver_presentation_jwt::verify_presentation_jwt;

#[post("/credentials")]
async fn issue_credential (
    req_body: web::Json<CredentialRequestDTO>, 
    pool: web::Data<Pool>,
    iota_state: web::Data<IotaState>,
    signer_data: web::Data<Arc<SignerMiddlewareShort>>,
    identity_sc_address: web::Data<String>
) -> Result<impl Responder, IssuerError> {
    log::info!("Issuing credential...");

    let credential_request = req_body.into_inner();
    let pg_client = &pool.get().await?;
    // read the request from the DB 
    let holder_request = pg_client.get_challenge(&credential_request.did).await?;
    log::info!("{:?}", holder_request);

    // resolve DID Doc and extract public key
    let holder_document = iota_state.client.resolve_did(&IotaDID::parse(holder_request.did_holder)?).await?;
    
    // Verify DID ownership, i.e. challenge signed equal to the stored nonce (anti replay)
    let _decoded_jws =  holder_document.verify_jws(
        &Jws::from(credential_request.identity_signature), // TODO: evaluate usage of auth header
        None,
        &EdDSAJwsVerifier::default(),
        &JwsVerificationOptions::default().nonce(&holder_request.challenge),
    )?;

    // Get the first free credential id from Identity Smart Contract
    let identity_addr: Address = Address::from_str(&identity_sc_address).map_err(|_| IssuerError::ContractAddressRecoveryError)?;
    let identity_sc = Identity::new(identity_addr, signer_data.get_ref().into());
    
    let credential_id = identity_sc.get_free_v_cid().call().await.map_err(|err| IssuerError::ContractError(err.to_string()))?;

    // Create and sign the credential
    let (credential_jwt, decoded_jwt_credential) = create_credential(
        &holder_document,
        &iota_state.issuer_document, 
        credential_id, 
        &iota_state.key_storage,
        &iota_state.issuer_identity.fragment,
        credential_request.credential_subject
    ).await.map_err(|_| IssuerError::OtherError("Conversion error".to_owned()))?;

    // Verify the EOA ownership
    log::info!("Wallet sign: {:?}", credential_request.wallet_signature);
    let wallet_sign = Signature::from_str(credential_request.wallet_signature.as_str())?;
    log::info!("signature {:?}", wallet_sign);
    let vm = holder_document.resolve_method("#ethAddress", None).ok_or(IssuerError::EthMethodNotFound)?;

    vm.type_().to_string().eq("EcdsaSecp256k1RecoverySignature2020").then(|| Some(())).ok_or(IssuerError::InvalidVerificationMethodType)?;
    
    let eth_addr = vm.data().custom()
    .take_if(|method_data| {method_data.name == "blockchainAccountId"} )
    .ok_or(IssuerError::InvalidVerificationMethodType)?
    .data.as_str()
    .ok_or(IssuerError::InvalidVerificationMethodType)?
    .strip_prefix("eip155:1:")
    .ok_or(IssuerError::InvalidVerificationMethodType)?;

    log::info!("eth addr: {}", eth_addr);
    let address: Address = eth_addr.parse().map_err(|_| IssuerError::AddressRecoveryError)?;

    wallet_sign.verify(holder_request.challenge.clone(), address)?;
    log::info!("Wallet signature verification success!");
    
    // Update Identity SC, addUser 
    update_identity_sc(
        identity_sc, 
        decoded_jwt_credential,
        credential_id, 
        holder_request.challenge,
        &credential_request.wallet_signature, 
    ).await?;

    pg_client.remove_challenge(&holder_document.id().to_string()).await?;

    let response = CredentialIssuedResponse { 
        message: "Verifiable Credential issued".to_owned(),
        issuer_did: iota_state.get_ref().issuer_identity.did.clone(),
        credential_id: credential_id,
        credential_jwt: credential_jwt
    };
    Ok(HttpResponse::Ok().json(response))
}

#[delete("/credentials/{credential_id}")] //, wrap = "from_fn(verify_presentation_jwt)")]
async fn revoke_credential (
    path: web::Path<i64>,
    eth_provider: web::Data<Arc<SignerMiddlewareShort>>,
    identity_sc_address: web::Data<String>,
) -> Result<impl Responder, IssuerError> {
    log::info!("Revoking credential...");
    let credential_id = path.into_inner();
    let client = eth_provider.get_ref().clone();
    let identity_addr: Address = Address::from_str(&identity_sc_address).map_err(|_| IssuerError::ContractAddressRecoveryError)?;
    let identity_sc = Identity::new(identity_addr, client);
    
    let call = identity_sc.revoke_vc(U256::from(credential_id));
    let pending_tx = call.send().await.map_err(|err| IssuerError::ContractError(err.to_string()))?;
    let receipt = pending_tx.confirmations(1).await.map_err(|err| IssuerError::ContractError(err.to_string()))?;

    let logs = receipt.ok_or(IssuerError::OtherError("No receipt".to_owned()))?.logs;

    // reading the log   
    for log in logs.iter() {
        let raw_log = RawLog {
            topics: log.topics.clone(),
            data: log.data.to_vec(),
        };
        // finding the event
        if let Ok(event) =  <VcRevokedFilter as EthEvent>::decode_log(&raw_log){
            log::info!("VcRevoked event:\n{:?}", event);
            return Ok(HttpResponse::Ok().finish());
        }
    }
    Err(IssuerError::OtherError("no VcRevoked event found in the receipt".to_owned()))
}


pub fn scoped_config(cfg: &mut web::ServiceConfig) {
    cfg
    .service(issue_credential)
    .service(revoke_credential);

}