//! Validated server secret used to derive accepted-IP hashes.

use std::fmt;

use crate::DpaAcceptanceError;

/// A validated, opaque 32-byte salt for `accepted_ip_hash`.
///
/// Its debug representation deliberately omits the secret bytes.
#[derive(Clone)]
pub struct IpHashSalt([u8; 32]);

impl IpHashSalt {
    /// Validate a provisioned salt. Missing, zero-filled, and non-32-byte
    /// values are rejected before a service can be constructed.
    ///
    /// # Errors
    ///
    /// Returns [`DpaAcceptanceError::InvalidIpHashSalt`] for invalid input.
    pub fn new(bytes: Option<&[u8]>) -> Result<Self, DpaAcceptanceError> {
        let bytes = bytes.ok_or(DpaAcceptanceError::InvalidIpHashSalt)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| DpaAcceptanceError::InvalidIpHashSalt)?;
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(DpaAcceptanceError::InvalidIpHashSalt);
        }
        Ok(Self(bytes))
    }

    /// Derive the persisted hash without exposing the secret bytes.
    #[must_use]
    pub fn hash_ip(&self, ip: &str) -> String {
        crate::locale::accepted_ip_hash(ip, &self.0)
    }
}

impl fmt::Debug for IpHashSalt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IpHashSalt([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::IpHashSalt;
    use crate::DpaAcceptanceError;

    #[test]
    fn rejects_missing_salt() {
        assert!(matches!(
            IpHashSalt::new(None),
            Err(DpaAcceptanceError::InvalidIpHashSalt)
        ));
    }

    #[test]
    fn rejects_wrong_length_salt() {
        assert!(matches!(
            IpHashSalt::new(Some(&[1; 31])),
            Err(DpaAcceptanceError::InvalidIpHashSalt)
        ));
        assert!(matches!(
            IpHashSalt::new(Some(&[1; 33])),
            Err(DpaAcceptanceError::InvalidIpHashSalt)
        ));
    }

    #[test]
    fn rejects_zero_salt_and_accepts_nonzero_32_bytes() {
        assert!(matches!(
            IpHashSalt::new(Some(&[0; 32])),
            Err(DpaAcceptanceError::InvalidIpHashSalt)
        ));
        assert!(IpHashSalt::new(Some(&[0x5a; 32])).is_ok());
    }

    #[test]
    fn debug_redacts_salt_bytes() -> Result<(), DpaAcceptanceError> {
        let salt = IpHashSalt::new(Some(&[0x5a; 32]))?;
        let debug = format!("{salt:?}");
        assert_eq!(debug, "IpHashSalt([REDACTED])");
        assert!(!debug.contains("5a"));
        Ok(())
    }
}
