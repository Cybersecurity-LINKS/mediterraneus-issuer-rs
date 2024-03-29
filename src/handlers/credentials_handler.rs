// SPDX-FileCopyrightText: 2024 Fondazione LINKS
//
// SPDX-License-Identifier: GPL-3.0-or-later

use actix_web::{web, HttpResponse, Responder, post};
use deadpool_postgres::Pool;
use serde_json::json;
use crate::dtos::identity_dtos::{CredentialRequestDTO, CredentialIssuedResponse};
use crate::IssuerState;
use crate::errors::IssuerError;
use crate::services::credentials_service::create_credential as create_credential_service;

#[post("")]
async fn create_credential (
    req_body: web::Json<CredentialRequestDTO>, 
    pool: web::Data<Pool>,
    issuer_state: web::Data<IssuerState>
) -> Result<impl Responder, IssuerError> {
    let (credential_id, credential_jwt) = create_credential_service(
        pool.get_ref().to_owned(),
        issuer_state.get_ref(), 
        req_body.into_inner()
    ).await?; 
    
    Ok(HttpResponse::Ok()
    .body(serde_json::to_string::<CredentialIssuedResponse>(
        &CredentialIssuedResponse { 
            message: "Verifiable Credential issued".to_string(),
            issuer_did: issuer_state.get_ref().issuer_identity.did.clone(),
            credential_id: credential_id,
            credential_jwt: credential_jwt
        })
    .unwrap()))
}

// TODO: revoke API (must be admin api to let only issuer revoke a VC)


pub fn scoped_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
         // prefixes all resources and routes attached to it...
        web::scope("/credentials")
            // .service(request_credential)
            // .service(activate_credential)
            .service(create_credential)

    );
}