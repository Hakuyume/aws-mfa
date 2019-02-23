mod yubikey;

use self::yubikey::Yubikey;
use failure::{format_err, Error};
use log::{info, warn};
use pcsc::{Context, Scope};
use std::time::{SystemTime, UNIX_EPOCH};

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
    let context = Context::establish(Scope::User)?;
    let mut buffer = Vec::new();
    let yubikey = Yubikey::connect(&context, &mut buffer)?;
    yubikey.select(&mut buffer)?;
    println!("Touch your YubiKey...");
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (digits, data) = yubikey.calculate(issuer, &(timestamp / 30).to_be_bytes(), &mut buffer)?;

    let offset = (data[data.len() - 1] & 0x0f) as _;
    let data = u32::from_be_bytes(unsafe { *(data[offset..offset + 4].as_ptr() as *const _) })
        & 0x7fffffff;
    let token_code = format!("{:01$}", data % 10_u32.pow(digits as _), digits as _);
    info!("token_code: {}", token_code);
    Ok(token_code)
}
