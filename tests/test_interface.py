import pathlib
import sys
import subprocess

import pytest

# Add the module directory to the path to ensure pytest runs even if the module is not installed.
PROJ_DIR = pathlib.Path(__file__).absolute().parent.parent
sys.path.insert(0, str(PROJ_DIR))

import bip39toolkit


VALID_PHRASE = "one hip six boy dog use win hat few act fly fox"
INVALID_PHRASE = "one hip six boy dog use win hat few act fly fly"

VALID_PHRASES = [
    "hen web toy kit few age bus car cup ice kid joy",
    "man put gym fee bus mad cup fit one end dad fog pet few gas",
    "off add net nut now cry dad kid oil zoo try toe fee boy mom art day shy",
    "one all tag leg two gas any can gun toy wet job dad shy tip cup own you toe way hat",
    "bar rib bus job fan lab add ice hen web fun tag gym sea fix say day fog top gun few fit era six",
]
VALID_SHARES = [
    "1: vacant summer universe fiscal grunt fiber caught impact inch palm client submit",
    "2: evoke stool shove lizard say oppose door bounce brass trophy decorate glue",
    "3: cave gorilla toast soup obscure canoe oxygen acquire diagram into enforce track",
]

VALID_ARGS = [
    [],
    ["generate"],
    ["generate", "12"],
    ["generate", "15"],
    ["generate", "18"],
    ["generate", "21"],
    ["generate", "24"],
    ["generate", "12", "--entropy", "123"],
    ["generate", "--entropy", "123"],
    ["generate", "--entropy", "123", "12"],
    ["generate", "--entropy", "123", "--deterministic"],
    ["generate", "--deterministic", "--entropy", "123"],
    ["share", "5", "3", VALID_PHRASE],
    ["share", "5", "3", VALID_PHRASE, "--deterministic"],
    ["share", "5", "3", VALID_PHRASE, "--deterministic", "--session", "friends"],
    ["share", "5", "3", VALID_PHRASE, "--session", "friends", "--deterministic"],
    ["share", "5", "--deterministic", "4", VALID_PHRASE],
    ["share", "--deterministic", "5", "3", VALID_PHRASE],
    ["share", "3", "5", VALID_PHRASE],
    ["share", "255", "255", VALID_PHRASE],
    ["recover", VALID_SHARES[0]],
    ["recover", VALID_SHARES[1]],
    ["recover", VALID_SHARES[2]],
    ["recover", VALID_SHARES[0], VALID_SHARES[1]],
    ["recover", VALID_SHARES[0], VALID_SHARES[2]],
    ["recover", VALID_SHARES[1], VALID_SHARES[2]],
    ["recover", VALID_SHARES[0], VALID_SHARES[1], VALID_SHARES[2]],
    ["recover", VALID_SHARES[2], VALID_SHARES[0], VALID_SHARES[1]],
    ["encode", "c4e3325cb7e993761e1d9cc14b9a184f"],
    ["encode", "c4e3325cb7e993761e1d9cc14b9a184fee3038e1"],
    ["encode", "c4e3325cb7e993761e1d9cc14b9a184fee3038e15b7878af"],
    ["encode", "c4e3325cb7e993761e1d9cc14b9a184fee3038e15b7878af3470492f"],
    ["encode", "c4e3325cb7e993761e1d9cc14b9a184fee3038e15b7878af3470492ffd62abff"],
    ["encode", "C4E3325CB7E993761E1D9CC14B9A184F"],
    ["encode", "c4e3325cb7e993761e1d9cc14b9a184f", "--hex"],
    ["encode", "--hex", "c4e3325cb7e993761e1d9cc14b9a184f"],
    ["encode", "--cards", "3C 7S 8C 3S JD 9C 8H 2D 4D TC AC 4H 9S 6H 5S QS AH 8S 2S KC QD QC TS 5C 5D TH 2C 6D 6S"],
    ["encode", "--indices", "723, 1646, 1035, 1284, 1053, 2046, 1899, 1292, 1558, 145, 390, 718"],
    ["decode", VALID_PHRASE, "--hex"],
    ["decode", VALID_PHRASE, "--indices"],
]

INVALID_ARGS = [
    ["generate", "9"],  # invalid phrase length
    ["generate", "27"],  # invalid phrase length
    ["generate", "48"],  # invalid phrase length
    ["generate", "12", "15"],  # multiple positional args
    ["generate", "--entropy"],  # missing value for keyword argument
    ["generate", "--entropy", "1", "--entropy", "2"],  # duplicate keyword argument
    ["generate", "--deterministic"],  # --deterministic requires `--entropy ENTROPY` to be specified
    ["share"],  # arguments missing
    ["share", "5"],  # threshold and phrase missing
    ["share", "5", "3"],  # phrase missing
    ["share", "0", "0", VALID_PHRASE],  # invalid number of shares and invalid threshold
    ["share", "0", "1", VALID_PHRASE],  # invalid number of shares
    ["share", "1", "0", VALID_PHRASE],  # invalid threshold
    ["share", "256", "3", VALID_PHRASE],  # invalid number of shares
    ["share", " -1", "3", VALID_PHRASE],  # invalid number of shares
    ["share", "5", "3", INVALID_PHRASE],  # invalid phrase
    ["share", "5", "3", VALID_PHRASE, "--session", "A"],  # --deterministic not specified
    ["recover"],  # no shares
    ["recover", VALID_PHRASE],  # phrase instead of share (no index)
    ["recover", f" -1: {VALID_PHRASE}"],  # share index out of range
    ["recover", f"0: {VALID_PHRASE}"],  # share index out of range
    ["recover", f"256: {VALID_PHRASE}"],  # share index out of range
    ["recover", VALID_SHARES[0], VALID_SHARES[0]],  # duplicate share indices
    [
        "recover",
        "1: brief deer rude scene dust hand street dry connect step ill tube",
        "2: nephew laugh rib divide recipe sign aware essay media goose again black still riot cattle",
    ],  # share of inconsistent length
    ["encode"],  # no input
    ["encode", "c4e3325cb7e993761e1d9cc14b9a184"],  # invalid length
    ["encode", "c4e3325cb7e993761e1d9cc14b9a184X"],  # invalid hexstring
    ["encode", "--dice", "c4e3325cb7e993761e1d9cc14b9a184f"],  # invalid format of the given input
    ["encode", "--hex", "--dice", "c4e3325cb7e993761e1d9cc14b9a184f"],
    ["encode", "--cards", "3Z 0S"],
    ["encode", "--indices", "1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 2048"],
    ["encode", "--indices", "1, 2, 3, 4, 5, 6, 7, 9, 10, 11, no-a-number"],
    ["decode"],
    ["decode", INVALID_PHRASE],
    ["decode", VALID_PHRASE, VALID_PHRASE],
    ["decode", VALID_PHRASE, "--dice"],
    ["decode", VALID_PHRASE, "--cards"],
    ["decode", VALID_PHRASE, "--hex", "--indices"],
    ["non-existing-command"],
    ["--no-command-with-invalid-flag"],
]

VALID_ARGS_WITH_EXECUTION_ERROR = [["encode", "--dice", "123456"]]


class CaptureFixture:
    """Class to simplify handling of checking stdout and stderr contents."""

    @property
    def stdout(self) -> str:
        self._update()
        return self._stdout

    @property
    def stderr(self) -> str:
        self._update()
        return self._stderr

    def __init__(self, capfd: pytest.CaptureFixture) -> None:
        self._capfd = capfd
        self._stdout = ""
        self._stderr = ""

    def _update(self) -> None:
        stdout, stderr = self._capfd.readouterr()
        self._stdout += stdout
        self._stderr += stderr


def cli_invoke(args: list[str]) -> None:
    """Call the this main script as if was invoked on the shell with the given parameter string."""
    subprocess.check_output(["./bip39toolkit.py", *args], text=True, timeout=15.0)


@pytest.mark.parametrize("args", VALID_ARGS)
def test_cli_invocation_with_valid_args__expect_completion_without_error(args: list[str]) -> None:
    cli_invoke(args)


@pytest.mark.parametrize("args", INVALID_ARGS)
def test_cli_invocation_with_invalid_args__expect_completion_without_error(args: list[str]) -> None:
    with pytest.raises(subprocess.CalledProcessError):
        cli_invoke(args)


@pytest.fixture
def capture(capfd: pytest.CaptureFixture) -> CaptureFixture:
    return CaptureFixture(capfd)


@pytest.mark.parametrize("args", VALID_ARGS)
def test_command_with_valid_args__expect_completion_without_error(args: list[str]) -> None:
    bip39toolkit.main(args)


@pytest.mark.parametrize("args", [v + ["--quiet"] for v in VALID_ARGS])
def test_command_with_valid_args_in_quiet_mode__expect_completion_without_error(args: list[str]) -> None:
    bip39toolkit.main(args)


@pytest.mark.parametrize("args", INVALID_ARGS)
def test_command_with_invalid_args__expect_app_argument_error(args: list[str]) -> None:
    with pytest.raises(bip39toolkit.AppArgumentError):
        bip39toolkit.main(args)


@pytest.mark.parametrize("args", [v + ["--quiet"] for v in INVALID_ARGS])
def test_command_with_invalid_args_in_quite_mode__expect_app_argument_error(args: list[str]) -> None:
    with pytest.raises(bip39toolkit.AppArgumentError):
        bip39toolkit.main(args)


@pytest.mark.parametrize("args", VALID_ARGS_WITH_EXECUTION_ERROR)
def test_command_with_valid_args__expect_app_execution_error(args: list[str]) -> None:
    with pytest.raises(bip39toolkit.AppExecutionError):
        bip39toolkit.main(args)


@pytest.mark.parametrize("args", [v + ["-h"] for v in VALID_ARGS] + [v + ["--help"] for v in VALID_ARGS])
def test_command_with_valid_args_and_help_flag__expect_usage_message(args: list[str], capture: CaptureFixture) -> None:
    bip39toolkit.main(args)
    assert "Usage" in capture.stdout
