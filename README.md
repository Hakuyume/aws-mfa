# Wrapper of AWS CLI for MFA

Currently, Yubikey (OATH-TOTP) is supported.

## Setup
1. Install [Yubico Authenticator](https://developers.yubico.com/yubioath-desktop/).
1. Configure your Yubikey as the virtual MFA device of your IAM account ([User Guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html#enable-virt-mfa-for-iam-user)).  
    *DO NOT CHOOSE U2F SECURITY KEY*

1. Configure `AWS CLI` ([User Guide](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html#cli-quick-configuration)).
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
