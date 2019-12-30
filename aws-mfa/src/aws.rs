use failure::{ensure, format_err, Fallible};
use futures::compat::Future01CompatExt;
use log::info;
use rusoto_iam::Iam;
use rusoto_sts::{Credentials, GetSessionTokenRequest, Sts};

pub(crate) async fn get_account_alias<C>(client: &C) -> Fallible<String>
where
    C: Iam,
{
    info!("iam list-account-aliases");
    let r = client
        .list_account_aliases(Default::default())
        .compat()
        .await?;
    info!("account aliases: {:?}", r);
    let account_alias = r
        .account_aliases
        .into_iter()
        .next()
        .ok_or_else(|| format_err!("No account alias"))?;
    info!("account alias: {}", account_alias);
    Ok(account_alias)
}

pub(crate) async fn get_caller_identity<C>(client: &C) -> Fallible<(String, String, String)>
where
    C: Sts,
{
    info!("sts get-caller-identity");
    let r = client
        .get_caller_identity(Default::default())
        .compat()
        .await?;
    info!("caller identity: {:?}", r);
    let account = r.account.ok_or_else(|| format_err!("No account"))?;
    info!("account: {}", account);
    let user_arn = r.arn.ok_or_else(|| format_err!("No user ARN"))?;
    info!("user ARN: {}", user_arn);
    let prefix = format!("arn:aws:iam::{}:user/", account);
    ensure!(
        user_arn.starts_with(&prefix),
        "Cannot detect user name from user ARN"
    );
    let user_name = user_arn[prefix.len()..].to_owned();
    info!("user name: {}", user_name);
    Ok((account, user_arn, user_name))
}

pub(crate) async fn get_session_token<C>(
    client: &C,
    account: &str,
    user_name: &str,
    token_code: &str,
) -> Fallible<Credentials>
where
    C: Sts,
{
    let serial_number = format!("arn:aws:iam::{}:mfa/{}", account, user_name);
    info!("serial number: {}", serial_number);
    info!("sts get-session-token");
    let r = client
        .get_session_token(GetSessionTokenRequest {
            duration_seconds: None,
            serial_number: Some(serial_number),
            token_code: Some(token_code.to_owned()),
        })
        .compat()
        .await?;
    info!("credentials: {:?}", r);
    r.credentials.ok_or_else(|| format_err!("No credentials"))
}
