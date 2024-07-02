// Copyright 2015-2021 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use crate::error::Error;
use crate::{der, signed_data, DerTypeId};
use pki_types::{CertificateDer, SignatureVerificationAlgorithm};
use signed_data::SubjectPublicKeyInfo;

/// A Raw Public Key certificate, used for connections using raw public keys as specified in RFC7250.
#[derive(Debug)]
pub struct RawPublicKeyEntity<'a> {
    inner: SubjectPublicKeyInfo<'a>,
}

impl<'a> TryFrom<&'a CertificateDer<'a>> for RawPublicKeyEntity<'a> {
    type Error = Error;

    /// Parse the ASN.1 DER-encoded SPKI encoding of the raw public key `cert`.
    /// Since we are parsing a raw public key, we first strip the outer sequence tag.
    fn try_from(cert: &'a CertificateDer<'a>) -> Result<Self, Self::Error> {
        let input = untrusted::Input::from(cert.as_ref());
        let spki = input.read_all(Error::TrailingData(DerTypeId::Certificate), |reader| {
            let untagged_spki = der::expect_tag(reader, der::Tag::Sequence)?;
            der::read_all::<SubjectPublicKeyInfo<'_>>(untagged_spki)
        })?;
        Ok(Self { inner: spki })
    }
}

impl<'a> RawPublicKeyEntity<'a> {
    /// Verifies the signature `signature` of message `msg` using a raw public key
    /// certificate, supporting RFC 7250.
    ///
    /// For more information on `signature_alg` and `signature` see the documentation for [`crate::end_entity::EndEntityCert::verify_signature`].
    pub fn verify_signature(
        &self,
        signature_alg: &dyn SignatureVerificationAlgorithm,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        let spki = self.inner.subject_public_key_info(true);
        signed_data::verify_signature(
            signature_alg,
            untrusted::Input::from(spki.as_ref()),
            untrusted::Input::from(msg),
            untrusted::Input::from(signature),
        )
    }
}

#[test]
#[cfg(feature = "alloc")]
fn test_ee_read_for_rpk_cert() {
    //Try to read an end entity certificate into a RawPublicKeyCert.
    //It will fail to parse the key value since we expect no unused bits.
    let ee = include_bytes!("../tests/ed25519/ee.der");
    let ee_der = CertificateDer::from(ee.as_slice());
    assert_eq!(
        RawPublicKeyEntity::try_from(&ee_der).expect_err("unexpectedly parsed certificate"),
        Error::TrailingData(DerTypeId::BitString)
    );
}

#[test]
#[cfg(feature = "alloc")]
fn test_spki_read_for_rpk_cert() {
    let pubkey = include_bytes!("../tests/ed25519/ee-pubkey.der");
    let spki_der = CertificateDer::from(pubkey.as_slice());

    let rpk_cert = RawPublicKeyEntity::try_from(&spki_der).expect("failed to parse certificate");

    // Retrieved the SPKI from the pubkey.der using the following commands (as in [`cert::test_spki_read`]):
    // xxd -plain -cols 1 tests/ed255519/ee-pubkey.der
    let expected_spki = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0xfe, 0x5a, 0x1e,
        0x36, 0x6c, 0x17, 0x27, 0x5b, 0xf1, 0x58, 0x1e, 0x3a, 0x0e, 0xe6, 0x56, 0x29, 0x8d, 0x9e,
        0x1b, 0x3f, 0xd3, 0x3f, 0x96, 0x46, 0xef, 0xbf, 0x04, 0x6b, 0xc7, 0x3d, 0x47, 0x5c,
    ];
    let expected_spki_verification = [
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0xfe, 0x5a, 0x1e, 0x36, 0x6c,
        0x17, 0x27, 0x5b, 0xf1, 0x58, 0x1e, 0x3a, 0x0e, 0xe6, 0x56, 0x29, 0x8d, 0x9e, 0x1b, 0x3f,
        0xd3, 0x3f, 0x96, 0x46, 0xef, 0xbf, 0x04, 0x6b, 0xc7, 0x3d, 0x47, 0x5c,
    ];
    assert_eq!(
        expected_spki,
        rpk_cert.inner.subject_public_key_info(false).as_ref()
    );
    assert_eq!(
        expected_spki_verification,
        rpk_cert.inner.subject_public_key_info(true).as_ref()
    )
}
