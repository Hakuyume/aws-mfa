use failure::{format_err, Error};
use futures::prelude::*;
use log::info;
use rusoto_iam::Iam;
use rusoto_sts::{Credentials, GetSessionTokenRequest, Sts};

pub fn get_account_alias<C>(client: &C) -> impl Future<Item = String, Error = Error>
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

pub fn get_caller_identity<C>(
    client: &C,
) -> impl Future<Item = (String, String, String), Error = Error>
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

pub fn get_session_token<C>(
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
