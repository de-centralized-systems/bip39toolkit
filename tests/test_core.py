import pathlib
import sys
import secrets

import pytest
from unittest import mock

# Add the module directory to the path to ensure pytest runs even if the module is not installed.
PROJ_DIR = pathlib.Path(__file__).absolute().parent.parent
sys.path.insert(0, str(PROJ_DIR))

import bip39toolkit
from bip39toolkit import (
    generate,
    share,
    recover,
    AppExecutionError,
)

VALID_PHRASE = "act act act act act act act act act act act box"
ZERO_PHRASE = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

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


@pytest.mark.parametrize("num_words", [12, 15, 18, 21, 24])
def test_generate__expect_correct_length_phrase(num_words: int) -> None:
    phrase = generate(num_words, deterministic=False, entropy=None)
    assert len(phrase.split()) == num_words


def test_generate__non_deterministic() -> None:
    A = generate(12, deterministic=False, entropy=None)
    B = generate(12, deterministic=False, entropy=None)
    assert A != B


def test_generate__bad_csprng() -> None:
    with mock.patch.object(secrets, "token_bytes") as mocked:
        mocked.return_value = b"\x00" * 32
        assert generate(12, deterministic=False, entropy=None) == ZERO_PHRASE


def test_generate__bad_csprng_with_user_entropy() -> None:
    with mock.patch.object(secrets, "token_bytes") as mocked:
        mocked.return_value = b"\x00" * 32
        assert generate(12, deterministic=False, entropy="some-user-entropy-mixed-in") != ZERO_PHRASE


def test_generate__deterministic() -> None:
    A = generate(12, deterministic=True, entropy="")
    B = generate(12, deterministic=True, entropy="")
    assert A == B


def test_generate__deterministic_but_different_behavior() -> None:
    A = generate(12, deterministic=True, entropy="A")
    B = generate(12, deterministic=True, entropy="B")
    assert A != B


def test_share__non_deterministic() -> None:
    A = share(VALID_PHRASE, 5, 3, deterministic=False, session=None)
    B = share(VALID_PHRASE, 5, 3, deterministic=False, session=None)
    assert A != B


def test_share__non_deterministic__shares_incompatible() -> None:
    A = share(VALID_PHRASE, 5, 3, deterministic=False, session=None)
    B = share(VALID_PHRASE, 5, 3, deterministic=False, session=None)
    assert recover([A[0], A[1], A[2]]) == VALID_PHRASE
    assert recover([B[0], B[1], B[2]]) == VALID_PHRASE
    assert recover([A[0], A[1], B[2]]) != VALID_PHRASE


def test_share__deterministic() -> None:
    A = share(VALID_PHRASE, 5, 3, deterministic=True, session=None)
    B = share(VALID_PHRASE, 5, 3, deterministic=True, session="")
    C = share(VALID_PHRASE, 5, 3, deterministic=True, session="C")
    assert A == B
    assert A != C


def test_selftest__triggers_on_bitflip() -> None:
    def flip_bit(phrase, num_shares, threshold, shares):
        index, value = bip39toolkit.bip39_decode_share(shares[0])
        value = bytearray(value)
        value[-1] ^= 0x01
        value = bytes(value)
        shares[0] = bip39toolkit.bip39_encode_share(index + 1, value)
        unpatched_run_selftest(phrase, num_shares, threshold, shares)

    unpatched_run_selftest = bip39toolkit.run_selftest
    with mock.patch.object(bip39toolkit, "run_selftest") as m:
        m.side_effect = flip_bit
        with pytest.raises(AppExecutionError):
            share(VALID_PHRASE, 5, 3)


def test_selftest__abort_after_timeout() -> None:
    def set_small_timeout(phrase, num_shares, threshold, shares):
        unpatched_run_selftest(phrase, num_shares, threshold, shares, timeout=0.1)

    unpatched_run_selftest = bip39toolkit.run_selftest
    with mock.patch.object(bip39toolkit, "run_selftest") as m:
        m.side_effect = set_small_timeout
        share(VALID_PHRASE, 50, 25)
