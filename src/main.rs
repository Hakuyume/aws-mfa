use rusoto_sts::{GetSessionTokenRequest, Sts, StsClient};
use std::process::{Command, Stdio};

fn main() {
    let client = StsClient::new(Default::default());
    let caller_identity = client
        .get_caller_identity(Default::default())
        .sync()
        .unwrap();
    let account = caller_identity.account.expect("Cannot fetch account");
    let user_arn = caller_identity.arn.expect("Cannot fetch ARN");
    let user_name = {
        let prefix = format!("arn:aws:iam::{}:user/", account);
        if user_arn.starts_with(&prefix) {
            &user_arn[prefix.len()..]
        } else {
            panic!("Cannot parse username from '{}'", user_arn);
        }
    };

    let output = Command::new("ykman")
        .arg("oath")
        .arg("code")
        .arg("--single")
        .arg(format!("Amazon Web Services:{}@", user_name))
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    if !output.status.success() {
        match output.status.code() {
            Some(code) => panic!("ykman failed with exit code {}", code),
            _ => panic!("ykman failed"),
        }
    }
    let token = String::from_utf8_lossy(&output.stdout).trim().to_owned();

    let credentials = client
        .get_session_token(GetSessionTokenRequest {
            duration_seconds: None,
            serial_number: Some(format!("arn:aws:iam::{}:mfa/{}", account, user_name)),
            token_code: Some(token),
        })
        .sync()
        .unwrap()
        .credentials
        .expect("Cannot fetch credentials");
    println!("{:?}", credentials);
}
