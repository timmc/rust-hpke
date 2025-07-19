use core::fmt;

use digest::{ExtendableOutput, Update};
use generic_array::typenum;
use kem::{Decapsulate, Encapsulate};
use rand_core::{CryptoRng, RngCore};
use rand_core_compat::Rng09;
use sha3::Shake256;
use subtle::{Choice, ConstantTimeEq};
use x_wing::{
    Ciphertext, DecapsulationKey, EncapsulationKey, CIPHERTEXT_SIZE, DECAPSULATION_KEY_SIZE,
    ENCAPSULATION_KEY_SIZE,
};

use crate::{
    kem::{Kem as KemTrait, SharedSecret},
    util::enforce_outbuf_len,
    Deserializable, HpkeError, Serializable,
};

// X-Wing v8 §7: Nsk of X-Wing is 32
type XWingPrivkeyLen = typenum::U32;
// X-Wing v8 §7: Npk of X-Wing is 1216
type XWingPubkeyLen = <typenum::U1000 as core::ops::Add<typenum::U216>>::Output;
// X-Wing v8 §7: Nenc of X-Wing is 1120
type XWingEncappedKeyLen = <typenum::U1000 as core::ops::Add<typenum::U120>>::Output;

/// An X-Wing private key.
#[derive(Clone)]
#[doc(hidden)]
pub struct PrivateKey {
    decaps: DecapsulationKey,
}

impl ConstantTimeEq for PrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        // TODO impl Eq in x-wing crate, which will obviate the copying here
        self.decaps.as_bytes().ct_eq(other.decaps.as_bytes())
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for PrivateKey {}

impl Serializable for PrivateKey {
    type OutputSize = XWingPrivkeyLen;

    fn write_exact(&self, buf: &mut [u8]) {
        // Check the length is correct and panic if not
        enforce_outbuf_len::<Self>(buf);
        buf.copy_from_slice(self.decaps.as_bytes());
    }
}

impl Deserializable for PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        let encoded: &[u8; DECAPSULATION_KEY_SIZE] = encoded
            .try_into()
            .map_err(|_| HpkeError::IncorrectInputLength(DECAPSULATION_KEY_SIZE, encoded.len()))?;

        Ok(PrivateKey {
            decaps: DecapsulationKey::from(*encoded),
        })
    }
}

/// An X-Wing public key.
#[derive(Clone)]
#[doc(hidden)]
pub struct PublicKey {
    encaps: EncapsulationKey,
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        // TODO impl Eq in x-wing crate, which will obviate the copying here
        self.encaps
            .as_bytes()
            .ct_eq(&other.encaps.as_bytes())
            .into()
    }
}

impl Eq for PublicKey {}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> fmt::Result {
        // TODO Better output here
        f.debug_struct("PublicKey")
            .field("pk_m", &format_args!("{:02X?}", self.encaps.as_bytes()))
            .finish()
    }
}

impl Serializable for PublicKey {
    type OutputSize = XWingPubkeyLen;

    fn write_exact(&self, buf: &mut [u8]) {
        // Check the length is correct and panic if not
        enforce_outbuf_len::<Self>(buf);
        buf.copy_from_slice(&self.encaps.as_bytes());
    }
}

impl Deserializable for PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        let encoded: &[u8; ENCAPSULATION_KEY_SIZE] = encoded
            .try_into()
            .map_err(|_| HpkeError::IncorrectInputLength(ENCAPSULATION_KEY_SIZE, encoded.len()))?;

        Ok(PublicKey {
            encaps: EncapsulationKey::from(encoded),
        })
    }
}

/// Holds the content of an encapsulated secret.
#[derive(Clone)]
#[doc(hidden)]
pub struct EncappedKey {
    ciph: Ciphertext,
}

impl Serializable for EncappedKey {
    type OutputSize = XWingEncappedKeyLen;

    fn write_exact(&self, buf: &mut [u8]) {
        // Check the length is correct and panic if not
        enforce_outbuf_len::<Self>(buf);
        buf.copy_from_slice(&self.ciph.as_bytes());
    }
}

impl Deserializable for EncappedKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        let encoded: &[u8; CIPHERTEXT_SIZE] = encoded
            .try_into()
            .map_err(|_| HpkeError::IncorrectInputLength(CIPHERTEXT_SIZE, encoded.len()))?;

        Ok(EncappedKey {
            ciph: Ciphertext::from(encoded),
        })
    }
}

#[doc = "Represents X-Wing v8"]
pub struct XWing;

impl KemTrait for XWing {
    // X-Wing v8 §7: Nsecret of X-Wing is 32
    #[doc(hidden)]
    type NSecret = typenum::U32;

    type EncappedKey = EncappedKey;
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;

    const KEM_ID: u16 = 0x647a;

    /// Deterministically derives a keypair from the given input keying material and ciphersuite
    /// ID. The keying material SHOULD have at least 256 bits of entropy.
    fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        // X-Wing v8 §5.6
        //
        // def DeriveKeyPair(ikm):
        // # Extract 32-byte seed from variable-length ikm using SHAKE.
        // sk = SHAKE256(ikm, 32*8)
        // return GenerateKeyPairDerand(sk)
        //
        // Note that this does not involve LabeledExtract/LabeledExpand,
        // unlike the other HPKE specs.

        let mut kdf_out = [0u8; 32];
        let mut kdf_hasher = Shake256::default();
        kdf_hasher.update(ikm);
        kdf_hasher.finalize_xof_into(&mut kdf_out);

        let sk = DecapsulationKey::from(kdf_out);
        let pk = sk.encapsulation_key();

        (PrivateKey { decaps: sk }, PublicKey { encaps: pk })
    }

    /// Converts an X-Wing private key to a public key
    fn sk_to_pk(sk: &PrivateKey) -> PublicKey {
        PublicKey {
            encaps: sk.decaps.encapsulation_key(),
        }
    }

    /// Does an X-Wing encapsulation. This does not support sender authentication.
    /// `sender_id_keypair` must be `None`. Otherwise, this returns
    /// [`HpkeError::AuthnotSupportedError`].
    fn encap<R: CryptoRng + RngCore>(
        pk_recip: &Self::PublicKey,
        sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        csprng: &mut R,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
        // X-Wing is not an authenticated KEM
        if sender_id_keypair.is_some() {
            return Err(HpkeError::AuthNotSupportedError);
        }

        let Ok((ciph, ss)) = pk_recip.encaps.encapsulate(&mut Rng09(csprng));

        // TODO: There's probably a nicer way to do this type conversion?
        let mut ss_out = <SharedSecret<XWing> as Default>::default();
        ss_out.0.copy_from_slice(&ss);
        Ok((ss_out, EncappedKey { ciph }))
    }

    /// Does an X-Wing decapsulation. This does not support sender authentication.
    /// `pk_sender_id` must be `None`. Otherwise, this returns
    /// [`HpkeError::AuthnotSupportedError`].
    fn decap(
        sk_recip: &Self::PrivateKey,
        pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<SharedSecret<Self>, HpkeError> {
        // X-Wing is not an authenticated KEM
        if pk_sender_id.is_some() {
            return Err(HpkeError::AuthNotSupportedError);
        }

        let Ok(ss) = sk_recip.decaps.decapsulate(&encapped_key.ciph);

        let mut ss_out = <SharedSecret<XWing> as Default>::default();
        ss_out.0.copy_from_slice(&ss);
        Ok(ss_out)
    }
}
