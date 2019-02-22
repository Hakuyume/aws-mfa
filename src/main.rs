use failure::{format_err, Error};
use futures::prelude::*;
use rusoto_iam::{Iam, IamClient};
use rusoto_sts::{Credentials, GetSessionTokenRequest, Sts, StsClient};
use std::collections::HashMap;
use std::process::{Command, Stdio};
use tokio_core::reactor::Core;
use tokio_process::CommandExt;

fn main() -> Result<(), Error> {
    let iam_client = IamClient::new(Default::default());
    let sts_client = StsClient::new(Default::default());

    let task = get_account_alias(&iam_client)
        .join3(get_caller_identity(&sts_client), get_yubikey_tokens())
        .and_then(|(account_alias, (account, _, user_name), tokens)| {
            println!("{:?}", tokens);
            get_session_token(&sts_client, &account, &account_alias, &user_name, &tokens)
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
    client
        .list_account_aliases(Default::default())
        .from_err()
        .and_then(|r| {
            r.account_aliases
                .into_iter()
                .next()
                .ok_or(format_err!("No account alias"))
        })
}

fn get_caller_identity<C>(client: &C) -> impl Future<Item = (String, String, String), Error = Error>
where
    C: Sts,
{
    client
        .get_caller_identity(Default::default())
        .from_err()
        .and_then(|r| {
            let account = r.account.ok_or(format_err!("No account"))?;
            let user_arn = r.arn.ok_or(format_err!("No user ARN"))?;
            let prefix = format!("arn:aws:iam::{}:user/", account);
            if user_arn.starts_with(&prefix) {
                let user_name = user_arn[prefix.len()..].to_owned();
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
    tokens: &HashMap<String, String>,
) -> impl Future<Item = Credentials, Error = Error>
where
    C: Sts,
{
    client
        .get_session_token(GetSessionTokenRequest {
            duration_seconds: None,
            serial_number: Some(format!("arn:aws:iam::{}:mfa/{}", account, user_name)),
            token_code: Some(
                tokens[&format!("Amazon Web Services:{}@{}", user_name, account_alias)].to_owned(),
            ),
        })
        .from_err()
        .and_then(|r| r.credentials.ok_or(format_err!("No credentials")))
}

fn get_yubikey_tokens() -> impl Future<Item = HashMap<String, String>, Error = Error> {
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
                parse_tokens(r.stdout)
            } else {
                Err(match r.status.code() {
                    Some(code) => format_err!("ykman failed with exit code {}", code),
                    _ => format_err!("ykman failed"),
                })
            }
        })
}

fn parse_tokens(ykman_out: Vec<u8>) -> Result<HashMap<String, String>, Error> {
    String::from_utf8(ykman_out)?
        .lines()
        .fold(Ok(HashMap::new()), |tokens, l| {
            tokens.and_then(|mut tokens| {
                let cols: Vec<_> = l.rsplitn(2, ' ').map(|col| col.trim()).collect();
                if cols.len() == 2 {
                    tokens.insert(cols[1].to_owned(), cols[0].to_owned());
                    Ok(tokens)
                } else {
                    Err(format_err!("Cannot parse '{}'", l))
                }
            })
        })
}
