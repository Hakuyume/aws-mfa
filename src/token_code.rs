use failure::{format_err, Error};
use log::{info, warn};
use std::process::{Command, Stdio};

pub fn get_token_code(issuer: &str) -> Result<String, Error> {
    get_token_code_from_yubikey(&issuer)
        .map_err(|err| {
            warn!("{}", err);
            err
        })
        .or_else(|_| get_token_code_from_prompt(&issuer))
}

fn get_token_code_from_prompt(issuer: &str) -> Result<String, Error> {
    Ok(rprompt::prompt_reply_stdout(&format!(
        "Enter token code for '{}' > ",
        issuer
    ))?)
}

fn get_token_code_from_yubikey(issuer: &str) -> Result<String, Error> {
    info!("ykman oath code --single {}", issuer);
    let output = Command::new("ykman")
        .arg("oath")
        .arg("code")
        .arg("--single")
        .arg(issuer)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()?;
    if output.status.success() {
        let token_code = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        info!("token code: {:?}", token_code);
        Ok(token_code)
    } else {
        Err(match output.status.code() {
            Some(code) => format_err!("ykman failed with exit code {}", code),
            _ => format_err!("ykman failed"),
        })
    }
}
