import pathlib
import sys

import pytest

# Add the module directory to the path to ensure pytest runs even if the module is not installed.
PROJ_DIR = pathlib.Path(__file__).absolute().parent.parent
sys.path.insert(0, str(PROJ_DIR))

from bip39toolkit import (
    xor_bytes,
    convert_dice_rolls_to_binary_string,
    convert_card_sequence_to_binary_string,
)


def test_xor_bytes():
    a = bytes.fromhex("b380740b6ed85b049a9fb45c8fa7f185")
    b = bytes.fromhex("da1d5305e4a0c03e350406fa7b852e61")
    a_xor_b = bytes.fromhex("699d270e8a789b3aaf9bb2a6f422dfe4")
    assert xor_bytes(a, b) == a_xor_b


def test_xor_bytes__error_on_unequal_length():
    a = bytes.fromhex("b380740b6ed85b049a9fb45c8fa7f185")
    b = bytes.fromhex("da1d5305e4a0c03e350406fa7b852e6100")
    with pytest.raises(ValueError):
        xor_bytes(a, b)


def test_convert_dice_rolls_to_binary_string():
    rolls = [int(d) for d in "1243152351541453343151323541235431254323543541543125356665412562441456654121246141256"]
    binary = (
        "01100110111"
        "01110110010"
        "11111011011"
        "01111011100"
        "11011101101"
        "10101110111"
        "01110011011"
        "01101111000"
        "00010011010"
        "01000010100"
        "00100110011"
        "00000100110"
        "100"
    )
    assert convert_dice_rolls_to_binary_string(rolls) == binary


def test_convert_card_sequence_to_binary() -> None:
    cards = "3C 7S 8C 3S JD 9C 8H 2D 4D TC AC 4H 9S 6H 5S QS AH 8S 2S KC QD QC TS 5C 5D TH 2C 6D 6S".split()
    binary = (
        "00010110100"
        "11110011011"
        "10100000010"
        "11101000001"
        "00100000111"
        "01111111111"
        "10111011010"
        "11101000011"
        "00110000101"
        "10000100100"
        "01001100001"
        "100101100"
    )
    assert convert_card_sequence_to_binary_string(cards) == binary
