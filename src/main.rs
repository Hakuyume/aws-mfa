use chrono::{DateTime, Duration, Utc};
use failure::{format_err, Error};
use futures::prelude::*;
use ini::Ini;
use log::info;
use rusoto_core::{
    credential::{DefaultCredentialsProvider, ProvideAwsCredentials},
    HttpClient,
};
use rusoto_iam::{Iam, IamClient};
use rusoto_sts::{Credentials, GetSessionTokenRequest, Sts, StsClient};
use std::env;
use std::process::{Command, Stdio};
use std::sync::Arc;
use tokio_core::reactor::Core;
use tokio_process::CommandExt;

fn main() -> Result<(), Error> {
    env_logger::init();
    let mut core = Core::new()?;

    let credentials_path = dirs::home_dir()
        .ok_or(format_err!("Cannot detect home directory"))?
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
        let task = get_account_alias(&iam_client)
            .join(get_caller_identity(&sts_client))
            .and_then(|(account_alias, (account, _, user_name))| {
                let issuer = format!("Amazon Web Services:{}@{}", user_name, account_alias);
                info!("issuer: {}", issuer);
                get_token_code_from_yubikey(&issuer)
                    .map(|token_code| (account, user_name, token_code))
            })
            .and_then(|(account, user_name, token_code)| {
                get_session_token(&sts_client, &account, &user_name, &token_code)
            });
        let credentials = core.run(task)?;

        credentials_ini
            .with_section(Some(&profile_name as &str))
            .set("aws_access_key_id", &credentials.access_key_id as &str)
            .set(
                "aws_secret_access_key",
                &credentials.secret_access_key as &str,
            )
            .set("aws_session_token", &credentials.session_token as &str)
            .set("aws_expiration", &credentials.expiration as &str);
        info!("save to: {}", credentials_path.display());
        credentials_ini.write_to_file(&credentials_path)?;
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

fn get_account_alias<C>(client: &C) -> impl Future<Item = String, Error = Error>
where
    C: Iam,
{
    info!("iam list-account-aliases");
    client
        .list_account_aliases(Default::default())
        .from_err()
        .and_then(|r| {
            info!("account aliases: {:?}", r);
            let account_alias = r
                .account_aliases
                .into_iter()
                .next()
                .ok_or(format_err!("No account alias"))?;
            info!("account alias: {}", account_alias);
            Ok(account_alias)
        })
}

fn get_caller_identity<C>(client: &C) -> impl Future<Item = (String, String, String), Error = Error>
where
    C: Sts,
{
    info!("sts get-caller-identity");
    client
        .get_caller_identity(Default::default())
        .from_err()
        .and_then(|r| {
            info!("caller identity: {:?}", r);
            let account = r.account.ok_or(format_err!("No account"))?;
            info!("account: {}", account);
            let user_arn = r.arn.ok_or(format_err!("No user ARN"))?;
            info!("user ARN: {}", user_arn);
            let prefix = format!("arn:aws:iam::{}:user/", account);
            if user_arn.starts_with(&prefix) {
                let user_name = user_arn[prefix.len()..].to_owned();
                info!("user name: {}", user_name);
                Ok((account, user_arn, user_name))
            } else {
                Err(format_err!("Cannot detect user name from user ARN"))
            }
        })
}

fn get_session_token<C>(
    client: &C,
    account: &str,
    user_name: &str,
    token_code: &str,
) -> impl Future<Item = Credentials, Error = Error>
where
    C: Sts,
{
    let serial_number = format!("arn:aws:iam::{}:mfa/{}", account, user_name);
    info!("serial number: {}", serial_number);
    info!("sts get-session-token");
    client
        .get_session_token(GetSessionTokenRequest {
            duration_seconds: None,
            serial_number: Some(serial_number),
            token_code: Some(token_code.to_owned()),
        })
        .from_err()
        .and_then(|r| {
            info!("credentials: {:?}", r);
            r.credentials.ok_or(format_err!("No credentials"))
        })
}

fn get_token_code_from_yubikey(issuer: &str) -> impl Future<Item = String, Error = Error> {
    info!("ykman oath code --single {}", issuer);
    Command::new("ykman")
        .arg("oath")
        .arg("code")
        .arg("--single")
        .arg(issuer)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn_async()
        .into_future()
        .and_then(|r| r.wait_with_output())
        .from_err()
        .and_then(|r| {
            if r.status.success() {
                let token_code = String::from_utf8_lossy(&r.stdout).trim().to_owned();
                info!("token code: {:?}", token_code);
                Ok(token_code)
            } else {
                Err(match r.status.code() {
                    Some(code) => format_err!("ykman failed with exit code {}", code),
                    _ => format_err!("ykman failed"),
                })
            }
        })
}
