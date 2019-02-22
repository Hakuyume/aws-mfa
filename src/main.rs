use failure::{format_err, Error};
use futures::prelude::*;
use log::info;
use rusoto_iam::{Iam, IamClient};
use rusoto_sts::{Credentials, GetSessionTokenRequest, Sts, StsClient};
use std::collections::HashMap;
use std::process::{Command, Stdio};
use tokio_core::reactor::Core;
use tokio_process::CommandExt;

fn main() -> Result<(), Error> {
    env_logger::init();

    let iam_client = IamClient::new(Default::default());
    let sts_client = StsClient::new(Default::default());

    let task = get_account_alias(&iam_client)
        .join3(get_caller_identity(&sts_client), get_yubikey_token_codes())
        .and_then(|(account_alias, (account, _, user_name), token_codes)| {
            get_session_token(
                &sts_client,
                &account,
                &account_alias,
                &user_name,
                &token_codes,
            )
        });

    let mut core = Core::new().unwrap();
    let credentials = core.run(task)?;
    println!("{:?}", credentials);
    Ok(())
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
    account_alias: &str,
    user_name: &str,
    token_codes: &HashMap<String, String>,
) -> impl Future<Item = Credentials, Error = Error>
where
    C: Sts,
{
    let serial_number = format!("arn:aws:iam::{}:mfa/{}", account, user_name);
    info!("serial number: {}", serial_number);
    let token_code = &token_codes[&format!("Amazon Web Services:{}@{}", user_name, account_alias)];
    info!("token code: {}", token_code);
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

fn get_yubikey_token_codes() -> impl Future<Item = HashMap<String, String>, Error = Error> {
    info!("ykman oath code");
    Command::new("ykman")
        .arg("oath")
        .arg("code")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn_async()
        .into_future()
        .and_then(|r| r.wait_with_output())
        .from_err()
        .and_then(|r| {
            if r.status.success() {
                let token_codes = parse_token_codes(r.stdout)?;
                info!("token codes: {:?}", token_codes);
                Ok(token_codes)
            } else {
                Err(match r.status.code() {
                    Some(code) => format_err!("ykman failed with exit code {}", code),
                    _ => format_err!("ykman failed"),
                })
            }
        })
}

fn parse_token_codes(ykman_out: Vec<u8>) -> Result<HashMap<String, String>, Error> {
    String::from_utf8(ykman_out)?
        .lines()
        .fold(Ok(HashMap::new()), |token_codes, l| {
            token_codes.and_then(|mut token_codes| {
                let cols: Vec<_> = l.rsplitn(2, ' ').map(|col| col.trim()).collect();
                if cols.len() == 2 {
                    token_codes.insert(cols[1].to_owned(), cols[0].to_owned());
                    Ok(token_codes)
                } else {
                    Err(format_err!("Cannot parse '{}'", l))
                }
            })
        })
}
