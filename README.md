# Wrapper of AWS CLI for MFA

Currently, Yubikey (OATH-TOTP) is supported.

## Setup
1. Install [Yubico Authenticator](https://developers.yubico.com/yubioath-desktop/).
1. Configure your Yubikey as the virtual MFA device of your IAM account (*DO NOT CHOOSE U2F SECURITY KEY*).
1. Setup `awscli`.
    ```
    $ aws configure
    ...
    ```
1. Install [Yubikey Manager CLI (ykman)](https://developers.yubico.com/yubikey-manager/).
1. Install aws-mfa.
    ```
    $ cargo install --git https://github.com/Hakuyume/aws-mfa.git
    ```

## Usage
```
$ aws-mfa aws ...
```
