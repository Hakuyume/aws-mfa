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
    use log::info;
    use std::time::{SystemTime, UNIX_EPOCH};
    use ykoath::Yubikey;

    let mut buf = Vec::new();
    let yubikey = Yubikey::connect(&mut buf)?;
    // TODO: handle the case that "the authentication object is set"
    info!("oath select: {:?}", yubikey.select(&mut buf)?);

    println!("Touch your YubiKey...");
    // https://github.com/Yubico/yubikey-manager/blob/b0b894906e450cff726f7ae0e71b329378b4b0c4/ykman/util.py#L400-L401
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (digits, data) =
        yubikey.calculate(true, issuer, &(timestamp / 30).to_be_bytes(), &mut buf)?;
    info!("oath calculate: {:?}", (digits, data));
    // https://github.com/Yubico/yubikey-manager/blob/b0b894906e450cff726f7ae0e71b329378b4b0c4/ykman/util.py#L371
    let data = u32::from_be_bytes(unsafe { *(data.as_ptr() as *const _) });
    let token_code = format!("{:01$}", data % 10_u32.pow(u32::from(digits)), digits as _);
    info!("token_code: {}", token_code);
    Ok(token_code)
}

#[cfg(not(feature = "yubikey"))]
fn get_token_code_from_yubikey(_: &str) -> Result<String, Error> {
    use failure::format_err;
    Err(format_err!("Yubikey support is disabled"))
}
