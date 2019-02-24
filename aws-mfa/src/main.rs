mod aws;
mod token_code;

use aws::*;
use chrono::{DateTime, Duration, Utc};
use failure::{format_err, Error};
use futures::prelude::*;
use ini::Ini;
use log::info;
use rusoto_core::{
    credential::{DefaultCredentialsProvider, ProvideAwsCredentials},
    HttpClient,
};
use rusoto_iam::IamClient;
use rusoto_sts::{Credentials, StsClient};
use std::env;
use std::process::Command;
use std::sync::Arc;
use token_code::get_token_code;
use tokio_core::reactor::Core;

fn main() -> Result<(), Error> {
    env_logger::init();
    let mut core = Core::new()?;

    let credentials_path = dirs::home_dir()
        .ok_or_else(|| format_err!("Cannot detect home directory"))?
        .join(".aws")
        .join("credentials");

    let provider = Arc::new(DefaultCredentialsProvider::new()?);
    let profile_name = {
        let credentials = core.run(provider.credentials())?;
        let access_key = credentials.aws_access_key_id();
        info!("access key (base): {}", access_key);
        format!("mfa/{}", access_key)
    };
    info!("profile name: {}", profile_name);

    info!("load from: {}", credentials_path.display());
    let mut credentials_ini = Ini::load_from_file(&credentials_path)?;
    let credentials = credentials_ini
        .section(Some(&profile_name as &str))
        .and_then(|sec| {
            Some(Credentials {
                access_key_id: sec.get("aws_access_key_id")?.to_owned(),
                secret_access_key: sec.get("aws_secret_access_key")?.to_owned(),
                session_token: sec.get("aws_session_token")?.to_owned(),
                expiration: sec.get("aws_expiration")?.to_owned(),
            })
        });

    if let Some(ref credentials) = credentials {
        info!("expiration: {}", credentials.expiration);
    } else {
        info!("expiration: N/A");
    }

    let credentials = if let Some(credentials) = credentials.filter(|credentials| {
        credentials
            .expiration
            .parse::<DateTime<Utc>>()
            .ok()
            .map_or(false, |expiration| {
                expiration >= Utc::now() + Duration::hours(3)
            })
    }) {
        credentials
    } else {
        let iam_client =
            IamClient::new_with(HttpClient::new()?, provider.clone(), Default::default());
        let sts_client =
            StsClient::new_with(HttpClient::new()?, provider.clone(), Default::default());

        let (account_alias, (account, _, user_name)) =
            core.run(get_account_alias(&iam_client).join(get_caller_identity(&sts_client)))?;
        let issuer = format!("Amazon Web Services:{}@{}", user_name, account_alias);
        info!("issuer: {}", issuer);
        let token_code = get_token_code(&issuer)?;
        let credentials = core.run(get_session_token(
            &sts_client,
            &account,
            &user_name,
            &token_code,
        ))?;

        credentials_ini
            .with_section(Some(&profile_name as &str))
            .set("aws_access_key_id", &credentials.access_key_id as &str)
            .set(
                "aws_secret_access_key",
                &credentials.secret_access_key as &str,
            )
            .set("aws_session_token", &credentials.session_token as &str)
            .set("aws_expiration", &credentials.expiration as &str);
        credentials_ini.write_to_file(&credentials_path)?;
        info!("save to: {}", credentials_path.display());
        credentials
    };

    let args: Vec<_> = env::args_os().collect();
    if args.len() == 1 {
        Ok(())
    } else {
        let status = Command::new(&args[1])
            .args(&args[2..])
            .env("AWS_ACCESS_KEY_ID", &credentials.access_key_id)
            .env("AWS_SECRET_ACCESS_KEY", &credentials.secret_access_key)
            .env("AWS_SESSION_TOKEN", &credentials.session_token)
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(match status.code() {
                Some(code) => format_err!("Command failed with exit code {}", code),
                _ => format_err!("Command failed"),
            })
        }
    }
}
