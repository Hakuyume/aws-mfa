# An AWS CLI helper for MFA

Currently, `aws-mfa` supports two methods.
- [Yubikey (OATH-TOTP)](https://developers.yubico.com/OATH/)
- Manual input (from your virtual device)

## Setup
1. (only Yubikey users) Configure your Yubikey as the virtual MFA device of your IAM account  
    ([User Guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html#enable-virt-mfa-for-iam-user), *DO NOT CHOOSE U2F SECURITY KEY*).  
    You can use [Yubico Authenticator](https://developers.yubico.com/yubioath-desktop/) to configure the Yubikey.
1. Configure `AWS CLI` ([User Guide](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html#cli-quick-configuration)).
    ```
    $ aws configure
    ...
    ```
1. Install aws-mfa.
    ```
    $ cargo install --git https://github.com/Hakuyume/aws-mfa.git
    ```

## Usage
```
$ aws-mfa aws ...
```
