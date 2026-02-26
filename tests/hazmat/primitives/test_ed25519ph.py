# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

"""
Tests for Ed25519ph (prehashed EdDSA, RFC 8032) support.

Ed25519ph uses SHA-512 to pre-hash the message before signing. When using
OpenSSL's EVP_DigestSign with the Ed25519ph instance, OpenSSL computes
SHA-512(message) internally. The caller passes the raw message, not the hash.

Go's crypto/ed25519 with Options{Hash: SHA512} expects the caller to pass
the pre-computed hash. Both approaches produce identical signatures because
both arrive at PH(M) = SHA-512(M) before applying dom2(1, context).
"""

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.exceptions import InvalidSignature


class TestEd25519phCrossValidation:
    """Cross-validate Ed25519ph signatures with Go test vectors.

    These vectors were generated using Go's crypto/ed25519 package with
    Options{Hash: SHA512, Context: "cluster-key-proof"}, which is the exact
    signing logic used by the SPIRL server's proof.go implementation.

    The Python sign_prehashed() method passes the raw message to OpenSSL,
    which computes SHA-512 internally. Go's Sign() receives the pre-computed
    SHA-512 hash. Both produce byte-identical signatures.
    """

    # SPIRL test key (first key from common/test/testkey/testdata/ed25519.pem)
    SEED = bytes.fromhex(
        "2d88c28fd501c157eb4d59f3e33f8d91e5fe1bc3c7cc56a513c3eab769482de5"
    )
    PUBLIC_KEY = bytes.fromhex(
        "aa5c7939d183bd0cd6569f088ad54760c052ccc4704559621f162cfa9db9e215"
    )

    def test_sign_with_context_and_payload(self):
        """Vector 1: Ed25519ph with context and extra payload."""
        key = Ed25519PrivateKey.from_private_bytes(self.SEED)
        message = bytes.fromhex(
            "0101010101010101010101010101010101010101010101010101010101010101"
            "0202020202020202020202020202020202020202020202020202020202020202"
            "746573742d7061796c6f6164"
        )
        context = b"cluster-key-proof"
        expected_sig = bytes.fromhex(
            "972c738626b4d1aed35bcfc7e9eac04ded8254d4adca890b560318bd2e3a1c72"
            "5b657481c381256f19e040a62173daa87c49d47b8cc8c683e031a9c2faf35a06"
        )

        sig = key.sign_prehashed(message, context=context)
        assert sig == expected_sig

        # Also verify with public key
        pub = key.public_key()
        pub.verify_prehashed(sig, message, context=context)

    def test_sign_with_context_no_payload(self):
        """Vector 2: Ed25519ph with context, no extra payload."""
        key = Ed25519PrivateKey.from_private_bytes(self.SEED)
        message = bytes.fromhex(
            "0101010101010101010101010101010101010101010101010101010101010101"
            "0202020202020202020202020202020202020202020202020202020202020202"
        )
        context = b"cluster-key-proof"
        expected_sig = bytes.fromhex(
            "71e86e73be71d6a6f4e49c822dfd421e36324ba04d58843fbb4fb497b89ced76"
            "bfca21ef2daff40885de28e5e09ed3dd1435b1706071609c178b3ce00c0dcb0f"
        )

        sig = key.sign_prehashed(message, context=context)
        assert sig == expected_sig

        pub = key.public_key()
        pub.verify_prehashed(sig, message, context=context)

    def test_sign_no_context(self):
        """Vector 3: Ed25519ph without context string."""
        key = Ed25519PrivateKey.from_private_bytes(self.SEED)
        message = bytes.fromhex(
            "0101010101010101010101010101010101010101010101010101010101010101"
            "0202020202020202020202020202020202020202020202020202020202020202"
            "746573742d7061796c6f6164"
        )
        expected_sig = bytes.fromhex(
            "0429f944bbbdbed27cdc76503ae109eb9b4b5202f805794318f5a4b0af36b6ac"
            "a1b7831376123886c2268608702ae4c6cc498443921c398b02bb9c156379960f"
        )

        sig = key.sign_prehashed(message)
        assert sig == expected_sig

        pub = key.public_key()
        pub.verify_prehashed(sig, message)

    def test_public_key_matches(self):
        """Verify the derived public key matches the expected value."""
        key = Ed25519PrivateKey.from_private_bytes(self.SEED)
        assert key.public_key().public_bytes_raw() == self.PUBLIC_KEY


class TestEd25519phRFC8032:
    """RFC 8032 Section 7.3 official Ed25519ph test vector."""

    SEED = bytes.fromhex(
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
    )
    PUBLIC_KEY = bytes.fromhex(
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"
    )

    def test_rfc8032_vector(self):
        """RFC 8032 7.3: Ed25519ph with message 'abc', no context."""
        key = Ed25519PrivateKey.from_private_bytes(self.SEED)
        assert key.public_key().public_bytes_raw() == self.PUBLIC_KEY

        message = b"abc"
        expected_sig = bytes.fromhex(
            "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41"
            "31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406"
        )

        sig = key.sign_prehashed(message)
        assert sig == expected_sig

        pub = key.public_key()
        pub.verify_prehashed(sig, message)


class TestEd25519phRoundtrip:
    """Roundtrip and negative tests for Ed25519ph."""

    def test_roundtrip(self):
        """Generate key, sign, verify roundtrip."""
        key = Ed25519PrivateKey.generate()
        message = b"roundtrip test message"
        context = b"test-context"

        sig = key.sign_prehashed(message, context=context)
        key.public_key().verify_prehashed(sig, message, context=context)

    def test_roundtrip_no_context(self):
        """Generate key, sign, verify without context."""
        key = Ed25519PrivateKey.generate()
        message = b"no context message"

        sig = key.sign_prehashed(message)
        key.public_key().verify_prehashed(sig, message)

    def test_wrong_signature_raises(self):
        """Corrupted signature must raise InvalidSignature."""
        key = Ed25519PrivateKey.generate()
        message = b"test message"
        sig = key.sign_prehashed(message)

        # Flip a bit in the signature
        bad_sig = bytearray(sig)
        bad_sig[0] ^= 0xFF
        bad_sig = bytes(bad_sig)

        with pytest.raises(InvalidSignature):
            key.public_key().verify_prehashed(bad_sig, message)

    def test_wrong_context_raises(self):
        """Different context on verify must raise InvalidSignature."""
        key = Ed25519PrivateKey.generate()
        message = b"test message"

        sig = key.sign_prehashed(message, context=b"context-a")

        with pytest.raises(InvalidSignature):
            key.public_key().verify_prehashed(sig, message, context=b"context-b")

    def test_wrong_message_raises(self):
        """Different message on verify must raise InvalidSignature."""
        key = Ed25519PrivateKey.generate()
        sig = key.sign_prehashed(b"message one")

        with pytest.raises(InvalidSignature):
            key.public_key().verify_prehashed(sig, b"message two")

    def test_ed25519_vs_ed25519ph_different_signatures(self):
        """Ed25519 and Ed25519ph produce different signatures for same input."""
        key = Ed25519PrivateKey.generate()
        message = b"same message"

        sig_plain = key.sign(message)
        sig_prehashed = key.sign_prehashed(message)

        assert sig_plain != sig_prehashed

    def test_context_too_long_raises(self):
        """Context > 255 bytes must raise ValueError."""
        key = Ed25519PrivateKey.generate()
        long_context = b"x" * 256

        with pytest.raises(ValueError, match="255"):
            key.sign_prehashed(b"data", context=long_context)

    def test_context_max_length_ok(self):
        """Context exactly 255 bytes must succeed."""
        key = Ed25519PrivateKey.generate()
        max_context = b"x" * 255

        sig = key.sign_prehashed(b"data", context=max_context)
        key.public_key().verify_prehashed(sig, b"data", context=max_context)
