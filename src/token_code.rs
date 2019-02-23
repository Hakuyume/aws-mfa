#[cfg(feature = "yubikey")]
mod yubikey;

use failure::Error;
use log::warn;

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

#[cfg(feature = "yubikey")]
fn get_token_code_from_yubikey(issuer: &str) -> Result<String, Error> {
    use self::yubikey::Yubikey;
    use log::info;
    use pcsc::{Context, Scope};
    use std::time::{SystemTime, UNIX_EPOCH};

    let context = Context::establish(Scope::User)?;
    let mut buffer = Vec::new();
    let yubikey = Yubikey::connect(&context, &mut buffer)?;
    yubikey.select(&mut buffer)?;
    println!("Touch your YubiKey...");
    // https://github.com/Yubico/yubikey-manager/blob/b0b894906e450cff726f7ae0e71b329378b4b0c4/ykman/util.py#L400-L401
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (digits, data) = yubikey.calculate(issuer, &(timestamp / 30).to_be_bytes(), &mut buffer)?;

    // https://github.com/Yubico/yubikey-manager/blob/b0b894906e450cff726f7ae0e71b329378b4b0c4/ykman/oath.py#L330-L331
    let offset = (data[data.len() - 1] & 0x0f) as _;
    // https://github.com/Yubico/yubikey-manager/blob/b0b894906e450cff726f7ae0e71b329378b4b0c4/ykman/util.py#L379-L380
    let data = u32::from_be_bytes(unsafe { *(data[offset..offset + 4].as_ptr() as *const _) })
        & 0x7fffffff;
    // https://github.com/Yubico/yubikey-manager/blob/b0b894906e450cff726f7ae0e71b329378b4b0c4/ykman/util.py#L371
    let token_code = format!("{:01$}", data % 10_u32.pow(digits as _), digits as _);
    info!("token_code: {}", token_code);
    Ok(token_code)
}

#[cfg(not(feature = "yubikey"))]
fn get_token_code_from_yubikey(_: &str) -> Result<String, Error> {
    use failure::format_err;
    Err(format_err!("Yubikey support is disabled"))
}
