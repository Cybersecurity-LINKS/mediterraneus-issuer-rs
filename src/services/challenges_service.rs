// SPDX-FileCopyrightText: 2024 Fondazione LINKS
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use deadpool_postgres::{Pool, Client as PostgresClient};
use identity_iota::core::{Timestamp, Duration};
use uuid::Uuid;

use crate::{errors::IssuerError, repository::operations::HoldersRequestsExt};

/// returns @true if the request can continue, @false if the holder has a pending request.
/// If the holder has an expired request, it gets cleared from the DB and the new one
/// will be inserted later by the handler (so the function will return true)
pub async fn check_and_clean_holder_requests(client: &PostgresClient, did: &String) -> Result<(), IssuerError> {
    
    match client.get_holder_request(did).await {
        Ok(holder_request) => {
            // request already exists
            // check that it is not expired, if expired remove from db
            let holder_request_timestamp = Timestamp::parse(&holder_request.clone().request_expiration).unwrap();
            if holder_request_timestamp < Timestamp::now_utc() {
                // request expired --> remove it from DB and let handler continue
                client.remove_holder_request(did).await?;
                Ok(())
            } else {
                // request still not expired --> stop handler from continuing
                Err(IssuerError::ChallengePendingError)
            }
        },
        Err(err) => Err(err),
    }
}

pub async fn get_challenge_service(pool: Pool, did: &String) -> Result<String, IssuerError>  {
    
    let client = &pool.get().await?;
    match check_and_clean_holder_requests(client, did).await {
        Ok(_) | Err(IssuerError::RowNotFound) => {
            // create nonce and store holder request (did, request expiration, nonce)
            let expiration = Timestamp::now_utc().checked_add(Duration::minutes(1)).unwrap();
            // let nonce = "0x".to_owned() + &Uuid::new_v4().simple().to_string();
            let nonce = Uuid::new_v4().to_string();
        
            log::info!("{},{}", did, nonce);
            client.insert_holder_request(
                did,
                expiration,
                &nonce
            ).await?;
        
            Ok(nonce)
        },
        Err(err) => Err(err),
    }
}


