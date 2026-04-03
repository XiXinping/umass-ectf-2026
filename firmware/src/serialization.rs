// ─── Custom serde for crypto types (no alloc needed) ────────────────

pub mod serde_signature {
    use p256::ecdsa::Signature;
    use serde::de::{self, Visitor};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(sig: &Signature, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(sig.to_bytes().as_ref())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Signature, D::Error> {
        struct V;

        impl<'de> Visitor<'de> for V {
            type Value = Signature;

            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str("64 bytes of ECDSA P-256 signature")
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Signature, E> {
                Signature::from_slice(v).map_err(E::custom)
            }
        }

        d.deserialize_bytes(V)
    }
}

pub mod serde_x25519_pubkey {
    use serde::de::{self, Visitor};
    use serde::{Deserializer, Serializer};
    use x25519_dalek::PublicKey;

    pub fn serialize<S: Serializer>(key: &PublicKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(key.as_bytes())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        struct V;

        impl<'de> Visitor<'de> for V {
            type Value = PublicKey;

            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str("32 bytes of X25519 public key")
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<PublicKey, E> {
                let bytes: [u8; 32] = v
                    .try_into()
                    .map_err(|_| E::custom("expected exactly 32 bytes"))?;
                Ok(PublicKey::from(bytes))
            }
        }

        d.deserialize_bytes(V)
    }
}

pub mod serde_uuid {
    use serde::de::{self, Visitor};
    use serde::{Deserializer, Serializer};
    use uuid::Uuid;

    pub fn serialize<S: Serializer>(uuid: &Uuid, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(uuid.as_bytes())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Uuid, D::Error> {
        struct V;

        impl<'de> Visitor<'de> for V {
            type Value = Uuid;

            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str("16 bytes of UUID")
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Uuid, E> {
                let bytes: [u8; 16] = v
                    .try_into()
                    .map_err(|_| E::custom("expected exactly 16 bytes"))?;
                Ok(Uuid::from_bytes(bytes))
            }
        }

        d.deserialize_bytes(V)
    }
}
