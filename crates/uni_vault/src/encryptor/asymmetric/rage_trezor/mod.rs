mod test;

use crate::{
    common::traits::JsonSerializable,
    re_export::std_anyhow::*,
    re_export::rage::*,
    encryptor::{
        asymmetric::{
            PublicKey,
            PublicKeyBuilder,
        },
        HasUserIdentifier,
        Encryptor,
        SecretType,
    }
};

pub use signature_to_keys::*;

use age::ssh::Recipient;

use std::io::Write;


/// Builds a new `RageTrezorVault` instance using the provided configuration.
///
/// # Example
///
/// ```
///    use uni_vault::encryptor::{
///        asymmetric::rage_trezor::{
///            RageTrezorEncryptorBuilder,
///            RageTrezorEncryptor,
///        },
///        Encryptor,
///        HasUserIdentifier,
///        SecretType,
///    };
///    use uni_vault::common::traits::JsonSerializable;
///    use uni_vault::common::test_helpers::{
///        TREZOR_ENCRYPT_COMMENT,
///        print_json_with_line,
///        debug_with_line
///    };
///
///    let password_for_test = 12345678.to_string();
///    let password_as_bytes = password_for_test.as_bytes();
///
///    let mut rage_trezor_encryptor: RageTrezorEncryptor = RageTrezorEncryptorBuilder::default()
///        .platform_id("uni.vault.onion")
///        .username("test_account")
///        .secret_type(SecretType::Password)
///        .bip32_path("m/44h/60h/11h/0/12")
///        .comment(TREZOR_ENCRYPT_COMMENT)
///        .build()
///        .unwrap();
///    print_json_with_line!(&rage_trezor_encryptor);
///
///    let encrypted_bytes = rage_trezor_encryptor.encrypt(password_as_bytes)
///        .unwrap();
///    print_json_with_line!(&rage_trezor_encryptor);
///
///    let decrypted_bytes = rage_trezor_encryptor.decrypt(&encrypted_bytes)
///        .unwrap();
///
///    assert_eq!(password_as_bytes, decrypted_bytes);
/// ```

#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
pub struct RageTrezorEncryptor {

    /// The identifier for the platform, such as "gmail.com".
    #[builder(setter(into))]
    pub platform_id: String,

    /// The username associated with the encryption process.
    #[builder(setter(into))]
    pub username: String,

    /// Type of secret being encrypted (e.g., Password, Text, etc.).
    #[builder(setter(into))]
    #[builder(default = "SecretType::Text")]
    pub secret_type: SecretType,

    /// BIP32 derivation path used for key generation.
    /// Default path "m/44h/60h/11h/0/12" is chosen for enhanced security over common paths.
    #[builder(setter(into))]
    #[builder(default = "\"m/44h/60h/11h/0/12\".to_string()")]
    pub bip32_path: String,

    /// Flag to indicate whether to create a new recipient or use existing ones.
    #[builder(setter(into))]
    #[builder(default = "true")]
    pub should_create_new_recipient: bool,

    /// from Identity
    #[builder(setter(into))]
    #[builder(default = "PublicKeyBuilder::default().build().unwrap()")]
    pub public_key: PublicKey,

    /// Set of recipients for encryption. Each string represents a recipient's identity.
    #[builder(setter(into))]
    #[builder(default = "HashSet::new()")]
    pub recipients: HashSet<String>,

    /// Additional comments or notes for this encryption instance.
    #[builder(setter(into))]
    #[builder(default = "\"\".to_string()")]
    pub comment: String,
}

impl JsonSerializable for RageTrezorEncryptor {}

impl HasUserIdentifier for RageTrezorEncryptor {
    /// Returns the username of the user associated with this encryptor instance.
    fn username(&self) -> String {
        self.username.clone()
    }

    /// Returns the platform ID associated with this encryptor.
    fn platform_id(&self) -> String {
        self.platform_id.clone()
    }

    /// Returns the type of secret this encryptor is handling.
    fn secret_type(&self) -> SecretType {
        self.secret_type.clone()
    }

    fn public_key_created_at(&self) -> String {
        self.public_key.public_key_created_at.clone()
    }
}

impl RageTrezorEncryptor {
    /// Retrieves or generates the list of recipients for encryption.
    ///
    /// If `should_create_new_recipient` is true or if there are no recipients or public_key,
    /// this function will generate a new recipient using the Trezor identity.
    pub fn get_rage_recipients(&mut self) -> anyhow::Result<Vec<Box<dyn age::Recipient>>> {
        if self.should_create_new_recipient ||
            self.recipients.is_empty() ||
            self.public_key.recipient_str.is_none() {
            let identity = self.get_rage_identity()?;
            let recipient = Recipient::try_from(identity)
                .unwrap()
                .to_string();

            self.recipients.insert(recipient.clone());
            self.should_create_new_recipient = false;
            self.public_key.recipient_str = Some(recipient);
        }

        let res = self.recipients.iter().map(|s| {
            let recipient = Recipient::from_str(s).unwrap();
            Box::new(recipient) as Box<dyn age::Recipient>
        }).collect();

        Ok(res)
    }

    /// Generates the Trezor identity based on the BIP32 path and a hint.
    pub fn get_rage_identity(&self) -> anyhow::Result<Identity> {
        let hint = self.generate_hint()
            .ok_or(anyhow::anyhow!("fail to generate hint"))?;

        let trezor_generator = TrezorGenerator::sign_with_bip32_path(
            &self.bip32_path,
            &hint
        )?;

        let identity = trezor_generator.generate_rage_identity()?;

        Ok(identity)
    }
}

impl Encryptor for RageTrezorEncryptor {
    /// Encrypts the given secret bytes using the Rage encryption scheme.
    fn encrypt(&mut self, secret: &[u8]) -> anyhow::Result<Vec<u8>> {
        let recipients = self.get_rage_recipients()?;
        let encryptor = age::Encryptor::with_recipients(
            &mut recipients.iter().map(|b| b.as_ref())
        ).unwrap();
        let mut encrypted_bytes = vec![];

        let mut writer = encryptor.wrap_output(&mut encrypted_bytes)?;
        writer.write_all(secret)?;
        writer.finish()?;
        Ok(encrypted_bytes)
    }

    /// Decrypts the given encrypted bytes using the Rage decryption scheme.
    fn decrypt(&self, encrypted_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        let identity = self.get_rage_identity()?;
        let decrypted_bytes = age::decrypt(&identity, encrypted_bytes)
            .map_err(Error::msg)?;

        Ok(decrypted_bytes)
    }


    // fn public_key(&self)-> Option<String> {
    // self.public_key.clone()
    // }



    /// Returns a descriptive name for this encryption method.
    fn name(&self) -> String {
        "Use Trezor ETH Signature as seed to generate an SSH private key and then generate a Rage key pair. Default BIP-32 path is m/44h/60h/11h/0/12".to_string()
    }
}
