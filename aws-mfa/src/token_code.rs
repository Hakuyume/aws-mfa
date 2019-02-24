use failure::{format_err, Error};
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
    use ykoath::{CalculateAllResponse, Yubikey};

    let mut buf = Vec::new();
    let yubikey = Yubikey::connect(&mut buf)?;
    // TODO: handle the case that "the authentication object is set"
    info!("oath select: {:?}", yubikey.select(&mut buf)?);

    // https://github.com/Yubico/yubikey-manager/blob/b0b894906e450cff726f7ae0e71b329378b4b0c4/ykman/util.py#L400-L401
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let challenge = (timestamp / 30).to_be_bytes();

    let entry = yubikey
        .calculate_all(true, &challenge, &mut buf)?
        .enumerate()
        .find(|(i, entry)| match entry {
            Ok(entry) => {
                info!("oath calculate all [{}]: {:?}", i, entry);
                entry.0 == issuer.as_bytes()
            }
            _ => true,
        })
        .ok_or_else(|| format_err!("No entry matched"))?
        .1?;

    let (digits, response) = match entry.1 {
        CalculateAllResponse::Response(digits, response) => Ok((digits, response)),
        CalculateAllResponse::Touch => {
            println!("Touch your YubiKey...");
            let (digits, response) =
                yubikey.calculate(true, issuer.as_bytes(), &challenge, &mut buf)?;
            info!("oath calculate: {:?}", (digits, response));
            Ok((digits, response))
        }
        CalculateAllResponse::HOTP => Err(format_err!("HOTP is not supported")),
    }?;

    // https://github.com/Yubico/yubikey-manager/blob/b0b894906e450cff726f7ae0e71b329378b4b0c4/ykman/util.py#L371
    assert_eq!(response.len(), 4);
    let response = u32::from_be_bytes(unsafe { *(response.as_ptr() as *const _) });
    let token_code = format!(
        "{:01$}",
        response % 10_u32.pow(u32::from(digits)),
        digits as _
    );
    info!("token_code: {}", token_code);
    Ok(token_code)
}

#[cfg(not(feature = "yubikey"))]
fn get_token_code_from_yubikey(_: &str) -> Result<String, Error> {
    Err(format_err!("Yubikey support is disabled"))
}
