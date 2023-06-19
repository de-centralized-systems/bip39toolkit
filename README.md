# BIP39 toolkit

The BIP39 toolkit is a self-contained command line application, which provides an interface to **generate**, secret **share** and **recover** BIP39 mnemonic phrases. The explicit goal of the tool is it to keep compatibility with the [BIP39 mnemonic format](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) and allow for sharing (and recovering) existing BIP39 phrases. 

The software is intend to be executed from a secure offline (ideally air gapped) system. Currently, the implementation supports various Linux based platforms and requires Python 3.10.6 or higher.

Hard- and software implementations using BIP39 often lack the support of non-English BIP39 phrases. We also limit the BIP39 toolkit to only support widely-established English BIP39 phrases. 

## Status

This software is currently in a **PRE-RELEASE** status.

We encourage people to test this software, provide feedback, or open issues. Further testing is required before we can consider it production-ready.


## Usage

To use the BIP39 toolkit, [download the bip39toolkit.py file](https://github.com/de-centralized-systems/bip39toolkit/releases/latest/download/bip39toolkit.py) from our [latest release](https://github.com/de-centralized-systems/bip39toolkit/releases/latest) and execute it in your favorite terminal.
```
$ chmod +x ./bip39toolkit.py
$ ./bip39toolkit.py
```

```
$ python3 bip39toolkit.py
```

You may also install the official python package using `pip`, and invoke it directly:
```
$ pip install bip39toolkit
$ bip39toolkit
```

The BIP39 toolkit provides the following commands. 
Please see the corresponding sections for a detailed description of each command.

- [`generate`](###generate-a-new-BIP39-phrase)  
  Generates a new BIP39 phrase using the system's cryptographically secure source of randomness.

- [`share`](###share-a-bip39-phrase)  
Splits the given BIP39 phrase into a set of $n$ shares such that at least $t$ shares are required to recover the original phrase.

- [`recover`](###recover-a-shared-bip39-phrase)  
Recover a previously shared BIP39 phrase from a set of at least $t$ shares.

- [`encode`](###encode-input-into-a-BIP39-phrase)  
  Converts entropy given in a range of different formats input (hex string, sequences of dice rolls, playing cards, or word indices) to the corresponding BIP39 phrase.

- [`decode`](###decode-a-bip39-phrase-into-other-formats)  
  Converts a given BIP39 phrase to a range of formats (hex string, sequence of word indices).


Executing the BIP39 toolkit without any parameters, or by specifying the `-h` or `--help` flags, prints a help message 
and exists.
```
./bip39toolkit.py --help
```
```
Usage: ./bip39toolkit.py [options] command [command_args]

BIP39 toolkit version: 0.1.0

The BIP39 toolkit provides a set of commands to generate new BIP39 phrases, share and recover
BIP39 phrases using Shamir Secret Sharing, and covert between various entropy formats and BIP39
phrases.

Available commands:
  generate       generate a new BIP39 phrase using the system's CSPRNG
  share          split the given BIP39 phrase into a set of `n` shares such that at least `t`
                 shares are required to recover the original phrase
  recover        recover a BIP39 phrase from a set of at least `t` shares
  encode         convert the given input to the corresponding BIP39 phrase
  decode         convert the given BIP39 phrase to the specified format

Options:
  -h, --help     show this help message and exit, additional information is available for each
                 command
  --quiet        suppress all non-essential output
```


### Generate a new BIP39 phrase

To generate a new BIP39 phrase, simply invoke the `generate` command without parameters. In this case
the toolkit uses the system's internal cryptographically secure random number generator to generate a new BIP39 phrase with a default length of 24 words and 256 bits of entropy.
```
$ ./bip39toolkit.py generate
```

Alternatively, the number of words can be passed as parameter. Suitable parameters are listed in the table below:

| **number of words** | **bits of entropy** |
| ------------------- | ------------------- |
| 12                  | 128 bits            |
| 15                  | 160 bits            |
| 18                  | 192 bits            |
| 21                  | 224 bits            |
| 24                  | 256 bits            |

For example, the command below generates a phrase with 12 words, corresponding to 128 bits of entropy:
```
$ ./bip39toolkit.py generate 12
```

Command output (different when re-executed): 
```
Generating a BIP39 phrase (12 words / 128 bits) using the system's internal cryptographically
secure random number generator (no additional user-supplied entropy is used).

"snake sign flame cruise radio motion card total diet wheat gap burden"
(SHA2-256 hash: 3d631297a41c2206a659fbb5072f3949ccb304b21a4cf23d3fe51d08584701ec)
```

> **NOTE:** In addition to the generated BIP39 phrase, the BIP39 toolkit outputs a the SHA2-256 hash of the generated phrase.
> This hash does not contain any secret information of the generated phrase and serves as a cryptographic commitment to the generated phrase. 
> It can, for example, be used to verify that 
> (i) the recovery of a shared phrase indeed returned the correct previously-shared value, or 
> (ii) that a share provided for recovery was not modified by accident or deliberately tampered with.


#### Additional user-provided entropy
Using the `--entropy` parameter, additional entropy can be provided by the user. This user-provided entropy is securely combined with the system's internal source of randomness. As long as either the system's internal source, or the user-provided entropy are of high quality, the generated BIP39 phrase is secure.

For example, a user may add ~130 bits of entropy by rolling a D20 dice 30 times:
```
$ ./bip39toolkit.py generate --entropy "6 9 16 17 14 3 2 14 13 16 19 7 4 3 4 2 7 4 7 6 19 7 18 14 1 12 8 3 4 6"
```

Command output (different when re-executed):
```
Generating a BIP39 phrase (12 words / 128 bits) using the system's internal cryptographically
secure random number generator (no additional user-supplied entropy is used).

"benefit design woman bind cement century reopen athlete rail rent divorce empower"
(SHA2-256 hash: 059bce279d56347862ab5aa89c02a8752c52cf5b13e113dee49209207e57590b)
```


#### Deterministic derivation
As an advanced feature, this toolkit provides the `--deterministic` flag to **deterministically convert** a string of user-provided entropy (given via the `--entropy` parameter) into a BIP39 phrase.

> **CAUTION:** This is considered an feature for **advanced users**. Using this features **disables the system's source of entropy** and only uses the user-provided entropy to derive the corresponding BIP39 phrase. Providing poor-quality entropy does lead to the generation of an **INSECURE** BIP39 phrase.

> **NOTE:** Implementation details of this feature may change in future versions of this software.

For example, the following command may be used to derive a BIP39 phases with 12 words from an alpha-numerical password. 
```
$ ./bip39toolkit.py generate 12 --deterministic --entropy "LqYhcN4dZYwfZi3TUfvAZt"
```

Command output:
```
Deterministically deriving a BIP39 phrase (12 words / 128 bits) from the user-supplied entropy.
CAUTION: The security of the generated phrase critically depends on the quality of the provided
entropy.

"zoo veteran inch news desk primary oyster perfect canoe author defy topple"
(SHA2-256 hash: f1c9e41705a73aa324336174f634c07f647c1379c8cf2ece9f7959ec67d07f1e)
```

Executing the command twice, even on different computers, always returns the same BIP39 phrase (subject to the above notice towards changes in future versions of this toolkit).


### Share a BIP39 phrase
The `share` command is used to split the given BIP39 phrase into a set of $n$ shares such that at least $t$ shares are required to recover the original phrase.
For this purpose, the parameters $n$, $t$, and the phrase to be shared are provided as positional arguments to the command. 
For example, to create 5 shares for a given phrase, out of which any set of (at least) 3 shares should sufficient to recover the given phrase, the following command is used:
```
./bip39toolkit.py share 5 3 "adjust indoor muscle hello orphan this fish slush hen surge fix salute"
````

Command output (different when re-executed):
```
BIP39 phrase loaded.

"adjust indoor muscle hello orphan this fish slush hen surge fix salute"
(SHA2-256 hash: f5126d3e90ebbdc30e888d34e67ff20ece97f7bf7cae05a065538a8c3bbb7de4)

Set up to generate n=5 secret shares for the given BIP39 phrase, such that t=3 shares are
required to recover the original phrase.
Sharing mode: randomized, resharing the same phrase will yield a different and incompatible set
of shares.

Running secret sharing procedure...
Shares created.

Executing selftest...
Selftest successful (all 16 combinations checked).

"1: brother prefer fly family leave gossip toward wave record manage wise sense"
(SHA2-256 hash: 03feb72a87529a0bbd80262b54a9e87fd829f0926cc01ea2d42097d7e9043876)

"2: elbow buffalo aunt skill angle dentist uncle strong robust ensure size since"
(SHA2-256 hash: 8668fd0c268377f6073a55c964d30adc16caaac2c0463708129a2b0598531e03)

"3: flame shuffle shrimp vendor turtle salt frog uncle glove blood horn remind"
(SHA2-256 hash: 29e2dd50de11b8aea4e65f2c6de333647a0b227fceb7d3c7ffd271b4f34a0a85)

"4: judge second never machine vivid meat during pole check print drive tent"
(SHA2-256 hash: fb0c2ba71d1b14b346288c4a56fb6d3a01b33ad2ec7e25deac0298c57b234251)

"5: guitar board frost saddle blade athlete void order zoo wait transfer penalty"
(SHA2-256 hash: d63763bfe02811170960fa8a7fd7546ebd594d564acfeb45c73e3fb2f1dcc216)
```

#### Determinstic sharing

As an advanced feature, the BIP39 toolkit support the deterministic generation of the shares using the `--deterministic` flag.
When using the `--deterministic` flag, the coefficients of the underlying secret sharing polynomials are derived from the phrase to be shared.
As a result, re-executing the sharing process for a particular phrase, and using the same value for recovery threshold $t$, leads to the generation of an identical set of shares.

The feature, can, for example, be used to re-generate a lost share, or create additional, yet-compatible shares a particular secret.

Usage example:
```
./bip39toolkit.py share 3 2 --deterministic "gasp patrol basket gather home pledge forward below stay filter absent tobacco"
```

Command output:
```
BIP39 phrase loaded.

"gasp patrol basket gather home pledge forward below stay filter absent tobacco"
(SHA2-256 hash: 0f6c5aec02174a1e479dbcdad4cfea34e33548a8f853b7b66a815d405475fafe)

Set up to generate n=3 secret shares for the given BIP39 phrase, such that t=2 shares are
required to recover the original phrase.
Sharing mode: deterministic, resharing the same phrase will yield the same set of shares.

Running secret sharing procedure...
Shares created.

Executing selftest...
Selftest successful (all 4 combinations checked).

"1: truck swing winter shield guitar fame person symptom comfort sweet dumb pencil"
(SHA2-256 hash: 187c62dff9576fe77fc0fa62e9e8d564b2d2363da44b8d9a8a1fd954beaf5f55)

"2: hard fatal envelope cabin suit draw shoulder lounge deputy outdoor economy glide"
(SHA2-256 hash: eab001df73396b67b1dae656ec43327ff979cfad17df309751645f750f724a3f)

"3: then concert pilot ring stable repair dinosaur equal screen axis air cat"
(SHA2-256 hash: 6dff51db45e46d457d12c97107a1fb29aa996c45f8d4e0ed0856517ae641338f)
```

```
$ ./bip39toolkit.py share 4 2 --deterministic "gasp patrol basket gather home pledge forward below stay filter absent tobacco"
```

Command output:
```
BIP39 phrase loaded.

"gasp patrol basket gather home pledge forward below stay filter absent tobacco"
(SHA2-256 hash: 0f6c5aec02174a1e479dbcdad4cfea34e33548a8f853b7b66a815d405475fafe)

Set up to generate n=3 secret shares for the given BIP39 phrase, such that t=2 shares are
required to recover the original phrase.
Sharing mode: deterministic, resharing the same phrase will yield the same set of shares.

Running secret sharing procedure...
Shares created.

Executing selftest...
Selftest successful (all 4 combinations checked).

"1: truck swing winter shield guitar fame person symptom comfort sweet dumb pencil"
(SHA2-256 hash: 187c62dff9576fe77fc0fa62e9e8d564b2d2363da44b8d9a8a1fd954beaf5f55)

"2: hard fatal envelope cabin suit draw shoulder lounge deputy outdoor economy glide"
(SHA2-256 hash: eab001df73396b67b1dae656ec43327ff979cfad17df309751645f750f724a3f)

"3: then concert pilot ring stable repair dinosaur equal screen axis air cat"
(SHA2-256 hash: 6dff51db45e46d457d12c97107a1fb29aa996c45f8d4e0ed0856517ae641338f)
```

#### Deterministic sharing using the `--session` parameter

The `--session` parameter, i.e., an arbitrary string using to identify a particular secret sharing instance, can be used in addition to the `--deterministic` flag, to create deterministically generate incompatible sets of shares for the same input phrase.
In the example below, 2 sets of shares (with 3 shares each) are deterministically generated. 
This is accomplished by invoking the BIP39 toolkit twice, first using the `--session A` parameter and then using the `--session B` parameter.
The underlying secret can be recovering from a subset of shares generated in session A, as well as using a subset of shares from session B.
However, shares from session A are incompatible with shares from session B.

```
./bip39toolkit.py share 3 2 --deterministic --session "A" "april right father slogan diagram episode boil oval laptop seed neck switch"
```

```
BIP39 phrase loaded.

"april right father slogan diagram episode boil oval laptop seed neck switch"
(SHA2-256 hash: bd3d3df71506817c00a0fa353a24e96fac870ccfb09481235fadde9c2c1206f8)

Set up to generate n=3 secret shares for the given BIP39 phrase, such that t=2 shares are
required to recover the original phrase.
Sharing mode: deterministic, resharing the same phrase will yield the same set of shares. The
session parameter 'A' is used for deriving the share. To get the same set of shares, reshare
using the same session parameter.  Using a different (or no) session parameter, resharing will
yield a different and incompatible set of shares.

Running secret sharing procedure...
Shares created.

Executing selftest...
Selftest successful (all 4 combinations checked).

"1: slender distance claim scare party sure coral verb patch north acid license"
(SHA2-256 hash: 3324ae743197b5621ab93d96ea4f7dcea34a88f9e034b408c720be2d64a2c266)

"2: near grape cannon team pizza trim chef dumb symptom robust jaguar goat"
(SHA2-256 hash: 6e7a1d4a1cb3e77ef183879eb66fb7ae569f0a7aacd7cece59f463af4898973f)

"3: fall together fork steak degree junk attack coast access useful tornado decade"
(SHA2-256 hash: d4694cc5801e760b47a893795edfc2e6a8d72d8de940b9d1f04c68f9faeaae90)
```

```
./bip39toolkit.py share 3 2 --deterministic --session "B" "april right father slogan diagram episode boil oval laptop seed neck switch"
```

```
BIP39 phrase loaded.

"april right father slogan diagram episode boil oval laptop seed neck switch"
(SHA2-256 hash: bd3d3df71506817c00a0fa353a24e96fac870ccfb09481235fadde9c2c1206f8)

Set up to generate n=3 secret shares for the given BIP39 phrase, such that t=2 shares are
required to recover the original phrase.
Sharing mode: deterministic, resharing the same phrase will yield the same set of shares. The
session parameter 'B' is used for deriving the share. To get the same set of shares, reshare
using the same session parameter.  Using a different (or no) session parameter, resharing will
yield a different and incompatible set of shares.

Running secret sharing procedure...
Shares created.

Executing selftest...
Selftest successful (all 4 combinations checked).

"1: antenna eager swamp bulk soccer sell speak hawk market march gather spoil"
(SHA2-256 hash: 1ed061eb399cc0fa2041b422054ca879d14375a7fdf97ca76dec972ee3059a1f)

"2: arrive enter little giraffe hub food melt figure middle doctor very school"
(SHA2-256 hash: 2dd3cf0917579ddce6035a3b7c05cbba86491fe014a79da7c15307a8b9279b84)

"3: autumn rent anxiety result panic spoil drop pen just air abuse soup"
(SHA2-256 hash: b5c8e4cbf0807a636e29ddc5dfdd630f1c98119dc666befd816affcfbe739381)
```


### Recover a shared BIP39 phrase
Recovers a previously shared BIP39 phrase from a set of at least $t$ shares.
To invoke the `recover` command, $t$ (or more) valid shared have to be passed as positional arguments to the command.
Each share consists of a share index (a number from 1-255), and a share value (12, 15, 18, 21, or 24 words).
Both the share index and the share value have to be passed for each share, using the following format:
```
"{index}: {word 1} {word 2} ... {word 12/15/18/21/24}"
```
All share indices have to be different.

The `recover` command first reads all given shares, 
lists each share in addition to the respective SHA2-256, which may be used by the user to verify the validity of the given share, 
then executes the recovery procedure of Shamir's Secret Sharing to 
finally display the recovered phrase with its SHA2-256 hash.

> Note: The BIP39 toolkit implements Shamir's Secret Sharing in its pure form, i.e., apart from basic input validation, the BIP39 toolkit does not automatically detect invalid, or deliberately crafted invalid shares. 
> If invalid or malicious shares are a concern, the user is require to compare the given SHA2-256 of each share and the recovered phrase to ensure correctness of the recovery.

> Note: If less than $t$ shares are passed to the `recover` command, the command will complete without error message, altough the recovered phrase and its SHA2-256 hash will be different from the phrase originally shared.

Example: Assume a BIP39 phrase has previously shared among $n=3$ parties, such that any set $t \geq 3$ parties can recover the shared phrase.
Then, the recovery procedure might be invoked using 3 shares, as illustrated below.
(Passing additional valid shares is possible and does not change the result.)

```
$ ./bip39toolkit.py recover "2: fun toast deer noble wish oxygen street regular ripple congress paddle solution" "3: analyst battle east analyst pelican jungle average dress key spatial common woman" "5: develop swarm behind pause supreme coach today absent skill crater hundred figure"
```

```
BIP39 shares loaded.

"2: fun toast deer noble wish oxygen street regular ripple congress paddle solution"
(SHA2-256 hash: 61855a0b2323c9be295aa3ebfbde595f30aa4f132c6f7bc6c0b090cd34805c23)

"3: analyst battle east analyst pelican jungle average dress key spatial common woman"
(SHA2-256 hash: eaddd35b07f264decc5fa0f2d2110cdb26c0ff8526453304b92cf40c7d7f0c18)

"5: develop swarm behind pause supreme coach today absent skill crater hundred figure"
(SHA2-256 hash: 2afd2158f02d3325d80e0ec10539a732dc3cc6c6726f26c3df430a2bc21fd5f4)

Running share recovery procedure...
BIP39 phrase recovered.

"raven maid copper question suit raise huge diary vast excess obtain fantasy"
(SHA2-256 hash: 666c6c6fd40c06936ed63593d6675bdc29db638851edcbc634a687fdf2c8e38c)
```

### Encode input into a BIP39 phrase
Converts entropy given in a range of different formats input (hex string, sequences of dice rolls, playing cards, or word indices) to the corresponding BIP39 phrase. 

> **CAUTION:** This is considered a feature for **advanced users**. Using this features only converts the user-provided entropy into the corresponding BIP39 phrase. Providing an input with poor quality leads to the generation of an **INSECURE** BIP39 phrase.

The length of the corresponding BIP39 phrase is automatically derived based on the number of entropy bits provided.
The input, after converting it into a binary format, is always left-trimmed to the match the exact number of required number for the longest possible BIP39 phrase.

| **bits of entropy** | **phrase length**           |
| ------------------- | --------------------------- |
| 0-127 bits          | ERROR: insufficient entropy |
| 128-159 bits        | 12 words                    |
| 160-191 bits        | 15 words                    |
| 192-223 bits        | 18 words                    |
| 224-255 bits        | 21 words                    |
| >= 256 bits         | 24 words                    |


For input formats which cannot be converted directly, i.e., a sequence of dice rolls or playing cards, a variable length encoding, ensuring an uniform distribution of the binary representation is used.
The encoding used is inspired by and compatible to the one used in the [Mnemonic Code Converter](https://iancoleman.io/bip39/) by Ian Coleman. Please see the table below for an input size reference. 
For variable length encodings, the table contains a suggestion (maximizing the probability of getting a phrase of a particular length) and the average number of rolls required to each particular word length.


| **desire phrase length** | **# hex chars** | **# dice rolls**   | **# playing cards** | **# word indices** |
| ------------------------ | --------------- | ------------------ | ------------------- | ------------------ |
| 12 words                 | 32              | *86 (avg: 76.8)*   | *32 (avg: 28.7)*    | 12                 |
| 15 words                 | 40              | *106 (avg: 96.0)*  | *39 (avg: 35.9)*    | 15                 |
| 18 words                 | 48              | *125 (avg: 115.2)* | *47 (avg: 43.0)*    | 18                 |
| 21 words                 | 56              | *144 (avg: 134.4)* | *54 (avg: 50.2)*    | 21                 |
| 24 words                 | 64              | *163 (avg: 153.6)* | *60 (avg: 57.4)*    | 24                 |

**Supported input formats**:
- a hexadecimal sequence of characters (0-9, a-f, A-F)  
  `--hex "ff8b25aa1b7651c10d8bcc32d72020e9"`  
  `--hex "FF8B25AA1B7651C10D8BCC32D72020E9"`
- a sequence of dice rolls (1-6)  
  `--dice "3353364512141455142546123155124226326624652524113212463623115216664564415221"`  
  `--dice "353336423442423425164123134341454632665446551262334124412143143562644624613165"`
- a sequence of playing cards (\[A2-9TJQK\]\[CDHS\])  
  `--cards "6H 5H 6C 6D QH 9D JS 2C TD 8S 6S 8D JS QD 5C 7C 6S QH 3H QD KH QH 9D KD 7H 8H AC 8S 3S"`
- a sequence of words indices (0-2047)  
  `--indices "2044, 713, 852, 439, 808, 1796, 433, 972, 406, 1480, 65, 1681"` 
 
For readability, the use of spaces, dashes, or colons are supported for all input formats.


**Example invocation:**

The above inputs can all be encoded to the same BIP39 phrase using the `encode` command, for example:
```
./bip39toolkit.py encode --indices "2044, 713, 852, 439, 808, 1796, 433, 972, 406, 1480, 65, 1681"
```

Command output:
```
Input loaded: [2044, 713, 852, 439, 808, 1796, 433, 972, 406, 1480, 65, 1681]

Converting the given list of word indices to the corresponding BIP39 phrase.
BIP39 phrase created.

"zebra float hedgehog dad govern they curtain kangaroo crazy ribbon amused split"
(SHA2-256 hash: dcf7b759acff5a612c526aca6fe7ec47ca1644cdd13d96f1a864f3b279a3044e)
```


### Decode a BIP39 phrase into other formats

The `decode` command is used to convert a given BIP39 phrase to a range of other formats.
Currently the two supported formats are
- a hexadecimal sequence of characters (0-9, a-f, A-F), using the `--hex` flag
- a sequence of word indices (0-2047), using the `--indices` flag

**Invocation example:**

```
./bip39toolkit.py decode --indices "zebra float hedgehog dad govern they curtain kangaroo crazy ribbon amused split"
```

Command output:
```
BIP39 phrase loaded.

"zebra float hedgehog dad govern they curtain kangaroo crazy ribbon amused split"
(SHA2-256 hash: dcf7b759acff5a612c526aca6fe7ec47ca1644cdd13d96f1a864f3b279a3044e)

Converting the given BIP39 phrase to a list of word indices.
Decoding completed.

"2044, 713, 852, 439, 808, 1796, 433, 972, 406, 1480, 65, 1681"
```


## Dependencies

The implementation does not use external dependencies.
The BIP39 toolkit supports any Python version after (and including) 3.9.0.\
It was extensively tested on Ubuntu 22.04.2 LTS using the following Python versions:
 - 3.9.0 
 - 3.9.16
 - 3.10.10
 - 3.11.2


## Development

A Makefile for development purposes is provided.  
It provides the following targets:
- **build:** to create the package for uploading to [PyPI](https://pypi.org/)
- **clean:** remove all build related files
- **coverage:** create a coverage report in html format using [`pytest-cov`](https://github.com/pytest-dev/pytest-cov)
- **test:** runs all unit tests using [`pytest`](https://pytest.org/)
- **upload:** publish the package to [pypi.org](https://pypi.org/)
- **upload-test:** publish the package to [test.pypi.org](https://test.pypi.org/)
- **venv:** sets up a virtual environment (`.venv` directory), 
  and install all development dependencies in this environment
