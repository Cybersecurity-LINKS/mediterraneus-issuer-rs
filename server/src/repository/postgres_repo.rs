// SPDX-FileCopyrightText: 2024 Fondazione LINKS
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;

use deadpool_postgres::{ManagerConfig, Pool, RecyclingMethod};
use tokio_postgres::NoTls;

use crate::utils::configs::DatabaseConfig;

pub async fn init(configuration: DatabaseConfig) -> Result<Pool> {
    log::info!("init database");

    let mut config = deadpool_postgres::Config::new();
    config.user = Some(configuration.db_user);
    config.password = Some(configuration.db_password.value());
    config.dbname = Some(configuration.db_name);
    config.host = Some(configuration.db_host);
    config.port = Some(configuration.db_port);

    config.manager = Some(ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    });
    let pool = config.create_pool(None, NoTls)?;
    log::info!("pool database");
    Ok(pool)
}
