//! Universal Vault implementation for secure data storage
//! 
//! This module provides the core functionality for storing and managing sensitive data
//! in both encrypted and unencrypted formats. It will support multiple encryption methods
//! including password-based encryption and hardware wallet (Trezor) based encryption.

use crate::{
    encryptor::{
        Encryptor,
        SecretType,
    },
    re_export::std_anyhow::*,
    common::traits::JsonSerializable
};

/// # Example
///
/// ```
/// use uni_vault::{
///     uni_vault::{
///         UniVault,
///         UniVaultBuilder,
///     },
///     encryptor::{
///         asymmetric::rage_trezor::{
///             RageTrezorEncryptorBuilder,
///             RageTrezorEncryptor,
///         },
///         Encryptor,
///         HasUserIdentifier,
///         SecretType,
///     },
///     re_export::std_anyhow::*,
///     common::traits::JsonSerializable,
///     common::test_helpers::{
///         TREZOR_ENCRYPT_COMMENT,
///         print_json_with_line,
///         debug_with_line
///     },
/// };
///
/// let password_for_test = 12345678.to_string();
/// let password_as_bytes = password_for_test.as_bytes();
/// let mut recipients_with_my_backup_key = HashSet::new();
/// recipients_with_my_backup_key.insert("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILD0y5DXSqOmx/Tf0pKP23+JrCVSUrezlPDf/vcFFt3s".to_string());
///
/// let mut rage_trezor_encryptor: RageTrezorEncryptor = RageTrezorEncryptorBuilder::default()
///     .platform_id("uni.vault.onion")
///     .username("test_account")
///     .should_create_new_recipient(true)
///     .recipients(recipients_with_my_backup_key)
///     .secret_type(SecretType::Password)
///     .bip32_path("m/44h/60h/11h/0/12")
///     .comment(TREZOR_ENCRYPT_COMMENT)
///     .build()
///     .unwrap();
///
/// let mut uni_vault: UniVault<RageTrezorEncryptor> = UniVaultBuilder::default()
///     .encryptor(rage_trezor_encryptor)
///     .data_type(SecretType::Password)
///     .data(password_as_bytes)
///     .build().unwrap();
/// print_json_with_line!(&uni_vault);
///
/// uni_vault.encrypt().unwrap();
/// print_json_with_line!(&uni_vault);
///
/// uni_vault.decrypt().unwrap();
/// print_json_with_line!(&uni_vault);
///
/// assert_eq!(password_as_bytes, uni_vault.data);
/// ```

#[derive(Debug, Clone, Serialize, Deserialize, Builder, Zeroize, ZeroizeOnDrop)]
pub struct UniVault<T: Encryptor + Serialize> {
    /// The encryption mechanism used by this vault.
    #[zeroize(skip)]
    pub encryptor: T,

    /// Type of data stored in the vault, which influences how the data is handled.
    #[zeroize(skip)]
    #[builder(setter(into))]
    #[builder(default = "SecretType::Text")]
    pub data_type: SecretType,

    /// Flag indicating whether the data in the vault is currently encrypted.
    #[zeroize(skip)]
    #[builder(setter(into))]
    #[builder(default = "false")]
    pub encrypted: bool,

    /// The actual data content of the vault, which could be plaintext or encrypted bytes.
    #[builder(setter(into))]
    #[builder(default = "Vec::new()")]
    pub data: Vec<u8>,
}

impl<T: Encryptor + Serialize + for<'de> Deserialize<'de>> JsonSerializable for UniVault<T> {}

impl<T: Encryptor + Serialize + for<'de> Deserialize<'de>> UniVault<T> {
    /// Encrypts the vault contents.
    /// 
    /// # Returns
    /// 
    /// Returns `Ok(())` if encryption is successful, or an `Error` if:
    /// - The data is already encrypted.
    /// - Encryption fails.
    pub fn encrypt(&mut self) -> anyhow::Result<()> {
        if self.encrypted {
            return Err(Error::msg("Do not encrypt already encrypted Bytes again"));
        }

        let encrypted_bytes = self.encryptor.encrypt(&self.data)?;
        self.data.zeroize();
        self.data = encrypted_bytes;
        self.encrypted = true;

        Ok(())
    }

    /// Decrypts the vault contents.
    /// 
    /// # Returns
    /// 
    /// Returns `Ok(())` if decryption is successful, or an `Error` if:
    /// - The data is not encrypted.
    /// - Decryption fails.
    pub fn decrypt(&mut self) -> anyhow::Result<()> {
        if !self.encrypted {
            return Err(Error::msg("Operation only supported on encrypted bytes"));
        }
        self.data = self.encryptor.decrypt(&self.data)?;
        self.encrypted = false;
        Ok(())
    }

    /// Decrypts and decodes a JSON string representation of a vault.
    ///
    /// This method parses a JSON string into a vault instance and then decrypts it.
    ///
    /// # Arguments
    ///
    /// * `json_str` - The JSON string representation of the vault.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Self)` if decryption and decoding are successful, or an `Error` if:
    /// - JSON parsing fails.
    /// - Decryption fails.
    pub fn decrypt_and_decode_json_string(
        json_str: &str,
    ) -> anyhow::Result<Self> {
        let mut uni_vault = UniVault::from_json(json_str)?;

        uni_vault.decrypt()?;

        Ok(uni_vault)
    }

    /// Converts the vault's data to a UTF-8 String.
    /// 
    /// This method will decrypt the data if it's encrypted before attempting to convert it to a String.
    ///
    /// # Returns
    /// 
    /// Returns `Ok(String)` if conversion is successful, or an `Error` if:
    /// - The data isn't valid UTF-8.
    /// - Decryption fails (if the data is encrypted).
    pub fn data_to_string(&mut self) -> anyhow::Result<String> {
        if self.encrypted {
            self.decrypt()?;
        }

        let data_str = String::from_utf8(self.data.clone())
            .map_err(Error::msg)?;

        Ok(data_str)
    }
}
