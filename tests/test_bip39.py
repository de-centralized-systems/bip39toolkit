import json
import pathlib
import sys

import pytest

# Add the module directory to the path to ensure pytest runs even if the module is not installed.
PROJ_DIR = pathlib.Path(__file__).absolute().parent.parent
sys.path.insert(0, str(PROJ_DIR))

from bip39toolkit import (
    bip39_encode_bytes,
    bip39_decode_phrase,
    bip39_verify_phrase,
    bip39_phrase_to_seed,
    bip39_encode_share,
    bip39_decode_share,
    bip39_verify_share,
)

VALID_PHRASE = "act act act act act act act act act act act box"

VALID_PHRASES = [
    "act act act act act act act act act act act box"
    "act act act act act act act act act act act act act act egg"
    "act act act act act act act act act act act act act act act act act oak"
    "act act act act act act act act act act act act act act act act act act act act boy"
    "act act act act act act act act act act act act act act act act act act act act act act act six"
]

INVALID_PHRASES_WITH_EXPECTED_ERRORS = [
    ("act!act!act!act!act!act!act!act!act!act!act!box", r".*invalid character*"),
    ("act act act act act act act act act act act zzz", r".*the word 'zzz' is not part of the BIP39 wordlist*"),
    (
        "act act act act act act act act act act yyy zzz",
        r".*the words 'yyy', and 'zzz' are not part of the BIP39 wordlist*",
    ),
    ("act act act act act act act act act act act act", r".*checksum verification failed*"),
    ("act act act act act act act act act act act act act", r".*invalid phrase length*"),
]


def load_test_vectors() -> list[tuple[bytes, str, str]]:
    """Load the BIP39 test vectors from local storage.
    Original source for test vectors: https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    """
    TESTVECTORS_PATH = PROJ_DIR / "tests" / "bip39_testvectors.json"
    with open(TESTVECTORS_PATH) as f:
        vectors = json.load(f)
    return [(bytes.fromhex(entropy), phrase, seed) for entropy, phrase, seed, _ in vectors["english"]]


BIP39_TEST_VECTORS = load_test_vectors()


@pytest.mark.parametrize("secret, phrase, seed", BIP39_TEST_VECTORS)
def test_encode_bytes__testvectors(secret: bytes, phrase: str, seed: str) -> None:
    assert bip39_encode_bytes(secret) == phrase


@pytest.mark.parametrize("secret, phrase, seed", BIP39_TEST_VECTORS)
def test_decode_phrase__testvectors(secret: bytes, phrase: str, seed: str) -> None:
    assert bip39_decode_phrase(phrase) == secret


@pytest.mark.parametrize("secret, phrase, seed", BIP39_TEST_VECTORS)
def test_seed_phrase__testvectors(secret: bytes, phrase: str, seed: str) -> None:
    assert bip39_phrase_to_seed(phrase, passphrase="TREZOR").hex() == seed


@pytest.mark.parametrize("secret, phrase, seed", BIP39_TEST_VECTORS)
def test_verify_phrase__testvectors(secret: bytes, phrase: str, seed: str) -> None:
    assert bip39_verify_phrase(phrase)


@pytest.mark.parametrize("sequence", [bytes(length) for length in [0, 1, 11, 13, 14, 15, 23, 25, 48]])
def test_encode_bytes__invalid_byte_sequence__expect_value_error(sequence: bytes) -> None:
    with pytest.raises(ValueError, match=".*Invalid number of bytes provided.*"):
        bip39_encode_bytes(sequence)


@pytest.mark.parametrize("phrase, expected_error_message", INVALID_PHRASES_WITH_EXPECTED_ERRORS)
def test_decode_phrase__invalid_phrase__expect_value_error(phrase: str, expected_error_message: str) -> None:
    with pytest.raises(ValueError, match=expected_error_message):
        bip39_decode_phrase(phrase)


@pytest.mark.parametrize("phrase, expected_error_message", INVALID_PHRASES_WITH_EXPECTED_ERRORS)
def test_verify_phrase__invalid_phrase__expect_value_error(phrase: str, expected_error_message: str) -> None:
    assert not bip39_verify_phrase(phrase)


@pytest.mark.parametrize("secret, phrase, seed", BIP39_TEST_VECTORS)
def test_verify_phrase__strict_mode_is_sensitive_to_whitespace(secret: bytes, phrase: str, seed: str) -> None:
    assert not bip39_verify_phrase(f" {phrase}", strict=True)
    assert not bip39_verify_phrase(f"{phrase} ", strict=True)
    assert not bip39_verify_phrase(phrase.replace(" ", "  "), strict=True)


@pytest.mark.parametrize("secret, phrase, seed", BIP39_TEST_VECTORS)
def test_encode_share__testvectors(secret: bytes, phrase: str, seed: str) -> None:
    for share_index in [1, 2, 47, 255]:
        share = bip39_encode_share(share_index, secret)
        assert str(share_index) in share and phrase in share


def test_encode_share__invalid_index() -> None:
    for share_index in [-1, 0, 256]:
        with pytest.raises(ValueError, match=r".*index invalid.*"):
            bip39_encode_share(share_index, bytes(16))


@pytest.mark.parametrize("secret, phrase, seed", BIP39_TEST_VECTORS)
def test_decode_and_verify_share__testvectors(secret: bytes, phrase: str, seed: str) -> None:
    for share_index in [1, 2, 47, 255]:
        assert bip39_decode_share(f"{share_index}: {phrase}") == (share_index, secret)
        assert bip39_verify_share(f"{share_index}: {phrase}")


def test_decode_and_verify_share__invalid_missing() -> None:
    with pytest.raises(ValueError, match=r".*index missing.*"):
        bip39_decode_share(VALID_PHRASE)
    assert not bip39_verify_share(VALID_PHRASE)


def test_decode_and_verify_share__index_out_of_range() -> None:
    for share_index in [-1, 0, 256]:
        with pytest.raises(ValueError, match=r".*out of the allowed range.*"):
            bip39_decode_share(f"{share_index}: {VALID_PHRASE}")
        assert not bip39_verify_share(f"{share_index}: {VALID_PHRASE}")


def test_decode_and_verify_share__index_invalid() -> None:
    with pytest.raises(ValueError, match=r".*share index invalid.*"):
        bip39_decode_share(f"not-a-number: {VALID_PHRASE}")
    assert not bip39_verify_share(f"not-a-number: {VALID_PHRASE}")


def test_verify_share__strict_mode_is_sensitive_to_whitespace() -> None:
    assert not bip39_verify_share(f" 47: {VALID_PHRASE}", strict=True)
    assert not bip39_verify_share(f"47: {VALID_PHRASE} ", strict=True)
    assert not bip39_verify_share(f"47:{VALID_PHRASE} ", strict=True)
