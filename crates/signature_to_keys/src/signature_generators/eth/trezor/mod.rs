// Test module for the current crate
mod tests;

// Import necessary dependencies from the crate
use crate::re_export::std_anyhow::*;
use crate::SignatureToKeyGenerator;

// Import external dependencies
use trezor_client::client::Signature;

use zeroize::{
    Zeroize,
    ZeroizeOnDrop,
};

// Derive macro for additional functionality like serialization, deserialization, and zeroization
#[derive(Debug, Builder, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct TrezorGenerator {
    /// BIP32 derivation path used for key generation. 
    /// Default path "m/44h/60h/11h/0/12" is chosen for enhanced security over common paths.
    #[builder(default = "\"m/44h/60h/11h/0/12\".to_string()")]
    #[builder(setter(into))]
    bip32_path: String,

    /// message
    #[builder(default = "\"This is a default message for testing Ethereum signature functionality. It has no financial or operational implications.\".to_string()")]
    #[builder(setter(into))]
    msg: String,

    /// Optional field to store the signature. 
    /// Wrapped in `Option` to handle the case where no signature has been generated yet.
    #[serde(skip_serializing)]
    #[zeroize]
    #[builder(default = "None")]
    signature: Option<Vec<u8>>,
}

// Implementing the `SignatureToKeyGenerator` trait for `TrezorGenerator`
impl SignatureToKeyGenerator for TrezorGenerator {
    /// Retrieve the stored signature or return an error if not available
    fn signature(&self) -> anyhow::Result<Vec<u8>> {
        let signature = self.signature.clone().ok_or(anyhow::anyhow!("have not signed"))?;
        Ok(signature)
    }

    fn message_info_json(&self) -> String {
        serde_json::json!({
            "message": self.msg,
            "bip32_path": self.bip32_path,
        }).to_string()
    }

    /// Generate a new instance by signing a message with a Trezor device using a BIP32 path
    fn sign_with_bip32_path(path: &str, hint_message: &str) -> anyhow::Result<Self> {
        let mut trezor_generator = TrezorGeneratorBuilder::default()
            .bip32_path(path)
            .build()
            .unwrap();
        let signature = trezor_generator.sign_msg_with_trezor(hint_message)?
            .as_bytes().to_vec();
        trezor_generator.signature = Some(signature);
        trezor_generator.msg = hint_message.to_string();

        Ok(trezor_generator)
    }
}

// Additional methods for `TrezorGenerator`
impl TrezorGenerator {
    /// Sign a message using a connected Trezor device
    pub fn sign_msg_with_trezor(&mut self, msg: &str) -> anyhow::Result<String> {
        // Connect to a unique Trezor device
        let mut connected_device = trezor_client::unique(false)?;
        connected_device.initialize(None)?;

        // Sign the message with Ethereum-specific signing method
        let signature = connected_device.ethereum_sign_message(
            msg.as_bytes().to_vec(),
            bip32_path_to_vec(&self.bip32_path)?,
        )?;

        self.msg = msg.to_string();
        Ok(signature_to_hex_string(&signature))
    }
}

/// Convert a BIP32 path string to a vector of u32 for use in hardware wallet operations
pub fn bip32_path_to_vec(s: &str) -> anyhow::Result<Vec<u32>> {
    s.split('/')
        .skip(1)
        .map(|part| {
            let is_hardened = part.ends_with('h') || part.ends_with('\'');
            let num_str = if is_hardened {
                &part[..part.len() - 1]
            } else {
                part
            };

            let num = num_str.parse::<u32>()?;

            Ok(if is_hardened { num | 0x80000000 } else { num })
        })
        .collect()
}

/// Convert a signature to a hexadecimal string format
pub fn signature_to_hex_string(signature: &Signature) -> String {
    let mut hex_string = String::new();

    // Convert 'r' component of the signature to hexadecimal
    for &byte in &signature.r {
        write!(hex_string, "{:02x}", byte).unwrap();
    }

    // Convert 's' component of the signature to hexadecimal
    for &byte in &signature.s {
        write!(hex_string, "{:02x}", byte).unwrap();
    }

    // Add the 'v' byte to the hexadecimal string
    write!(hex_string, "{:02x}", signature.v).unwrap();

    // Format the result with a '0x' prefix for Ethereum compatibility
    format!("0x{}", hex_string)
}
