
# DRAFT: Shamir Secret Sharing for BIP39 Mnemonic Phrases

Authors: Philipp Schindler, Aljosha Judmayer  
Status: DRAFT  
Version: 0.1  
Last revision: 2023-06-19  
Initial release: -  
<!-- Ensure the above lines are terminated with two spaces to insert the desired line breaks. -->

This work is licensed under the [Creative Commons Attribution 4.0 International License](http://creativecommons.org/licenses/by/4.0/).

[![License: CC BY 4.0](https://img.shields.io/badge/License-CC_BY_4.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)



## Abstract 

This document specifies a Shamir secret sharing scheme for sharing [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) mnemonic phrases. 
The goal of this specification is it to be fully compatible with existing encodings of BIP39 mnemonic phrases.
With this focus in mind, this scheme may be used share mnemonic phrases for hierarchical deterministic (HD) cryptocurrency wallets which accept BIP39 mnemonics as input. 
It can be used to split a given (already existing) BIP39 mnemonic phrase of 12, 15, 18, 21, or 24 words, 
into up to $n = 255$ shares, such that any configurable subset of shares of size $t \leq n$ can be used to recover the original mnemonic phrase from the shares.
The individual shares are encoded as BIP39 mnemonics themselves, so that they can be transcribed easily, and/or shared as well using the same tool in a recursive manner. 
Templates for transcribing the necessary information are available [here](TODO). 

The secret sharing design is intentionally kept as simple as possible, and as close as possible to the original secret sharing approach described by [Shamir (1979)](https://dl.acm.org/doi/pdf/10.1145/359168.359176).
This specification is targeted to the use BIP39 for encoding and decoding of mnemonic phrases, but the secret sharing is performed on the level of byte sequences. 
Therefore, alternative encodings such as, e.g., [bytewords](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-012-bytewords.md), may be used in other implementations instead of BIP39.


## Status of This Memo

This document is not an official standard; it is published without any warranty for informational purposes and aims to consolidate community best practices, foster public review as well as contribution and 
motivate the creation of official standards based on the herein provided material. 

Information about the current status of this document, any errata, and how to provide feedback on it may be obtained at: [https://github.com/de-centralized-systems/bip39toolkit](https://github.com/de-centralized-systems/bip39toolkit)


## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", 
"NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 
([RFC2119](https://tools.ietf.org/html/rfc2119), [RFC8174](https://tools.ietf.org/html/rfc8174)) when, and only when, 
they appear in all capitals, as shown here.

## Introduction

The demand of deriving and managing an increasing number of secret keys has risen in recent years.
This is mostly due to the widened adoption of cryptocurrencies and their increase in valuation. 
These developments have fostered the creation of several different approaches to derive, encode and manage cryptographic keying material, within the respective community.

This specification attempts to consolidate community best practices and well known and established cryptographic techniques, in relation to the secret sharing of cryptographic keying material.
The aim of this document is to specify a minimalistic, interoperable and backward compatible method for the secret sharing of cryptographic keying material intended for manual/human processing, e.g., as used in private offline/paper backups of existing BIP39 mnemonic seed phrases. 

### <a name="Scope"></a>Scope, Goals and Non-goals

To clarify the scope of this document, the relation to other processing steps in deriving and managing cryptographic keying material is outlined in the following.

* **Generation of a cryptographic key**  
At this point a new key $s$ is generated from a cryptographically secure source of randomness. 
In most cases, this marks the first step in a hierarchically deterministic derivation of further keying material. 
Therefore, an initial key is sometimes also called *seed-key*. 
This step is not within the scope of this document and MUST have taken place before the herein specified scheme can be 
applied to a key $s$. 

* **Mnemonic encoding/decoding of a cryptographic key**  
A generated or derived key $s$ can be represented as a mnemonic phrase to improve human readability and easier manual 
copying of keying material or key shares. 
Examples for such schemes are 
[BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki), or 
[bytewords](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-012-bytewords.md).
This step is out-of-scope of this document and such techniques SHOULD be used in combination with the herein specified 
scheme. 

* **Secret sharing of a cryptographic key**  
A generated or derived key $s$ is shared among a set of $n$ participants, where $t$ should be able to reconstruct the original key $s$. 
In this specification, we focus exclusively on this step.

#### Goals
- Describe a simple scheme usable with existing BIP39 mnemonic phrases and based on classical Shamir Secret Sharing (SSS).
- Enable reproducibility through deterministic sharing sessions, which always generate the exact same shares given the same secret and the same session id. 
- Provide additional verification hashes for (manually) detecting invalid/manipulated shares to prevent invalid reconstructions.

#### Non-Goals 
- Specification of how the input key $s$ has to be created, despite enforcing a minimum entropy of 128 bit. 
- Specification of the mnemonic encoding scheme used for input and output data.
- Specification of further hidden derivation steps for plausible deniability or and additional layers of security. 

### Background

This specification is based on [Shamir Secret Sharing](https://dl.acm.org/doi/pdf/10.1145/359168.359176) 
(SSS).
Thus, the specified scheme is intended to share high min-entropy cryptographic keying material, i.e., a secret $s$, among a set of $n$ participants, such that at least $t$ are required to reconstruct the original secret $s$. 
A detailed comparison between related implementations of secret sharing schemes based on SSS and utilized in this context of cryptocurrencies (like
[SLIP39](https://github.com/satoshilabs/slips/blob/master/slip-0039.md),
[BC-SSKR](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-011-sskr.md),
[Shamir39](https://iancoleman.io/shamir39/), 
[BIP93](https://github.com/bitcoin/bips/blob/master/bip-0093.mediawiki) etc.) is out of scope of this document. 

### Notation and Symbols

The following table provides an overview of the used notation in the remainder of this document.

| Symbol                  | Description                                                                                                                                                                                                   |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| $n$                     | the total number of shares to be created $\left(1 \leq n \leq 255\right)$                                                                                                                                     |
| $t$                     | the minimum number of shares required for the recovery process $\left(1 \leq t \leq n\right)$                                                                                                                 |
| $b$                     | the number of bytes of a given secret or share                                                                                                                                                                |
| $s$                     | the secret value to be shared, represented by a sequence of $b$ bytes                                                                                                                                         |
| $i$                     | an index variable used for the secret shares; $1 \leq i \leq n$                                                                                                                                               |
| $j$                     | an index variable used for the coefficient of the secret sharing polynomials $0 \leq j < t$, or loop variable for the individual share in the set of collected shares during reconstruction $0 < j < t$       |
| $m$                     | a loop variable for the individual share in the set of collected shares during reconstruction $0 < m < t$                                                                                                     |
| $k$                     | an index variable used to denote the $k^\textsf{th}$ byte in the secret, a share or the $k^\textsf{th}$ secret sharing polynomial; $0 \leq k < b$                                                             |
| $s_i$                   | a share of the secret $s$; consists of a share index $x_i$ (an integer between $1$ and $255$) and share value $y_i$ (a sequence of $b$ bytes)                                                                 |
| $c_j$                   | the $j^{\textsf{th}}$ coefficients of the secret sharing polynomials as a sequence of $b$ bytes; the byte $c_j[k]$ represents the $j^{\textsf{th}}$ coefficient of the secret sharing polynomial $f_k(\cdot)$ |
| $f_k(\cdot)$            | the secret sharing polynomial used to share the $k^{\textsf{th}}$ byte of the secret $s$                                                                                                                      |
| $\alpha \mid\mid \beta$ | the concatenation of two sequences of bytes $\alpha$ and $\beta$                                                                                                                                              |
| $\alpha[k]$             | the $k^\textsf{th}$ byte of the sequence of bytes $\alpha$, 0-based indices used                                                                                                                              |
| $\alpha[:k]$            | the first $k$ bytes of the sequence of bytes $\alpha$                                                                                                                                                         |
| $\textsf{bip39}(\cdot)$ | Function that returns the BIP39 mnemonic encoding of a given secret $s$ or the share $s_i$ of a shared secret.                                                                                                |


## <a name="Sharing"></a>Sharing

In the following, we specify the process of creating $n$ shares $(s_1, s_2, ..., s_n)$ for a given 
secret $s$ (a sequence of $b \geq 16$ bytes) such that any subset of at least $t$ of those shares can be used to recover the shared value.

**Input:** 
 - $\mathbf{s}$: The secret to be shared, i.e., a sequence of $b$ bytes, where $b \geq 16$.
 - $\mathbf{n}$: The number of shares to be generated, $1\leq n \leq 255$.
 - $\mathbf{t}$: The secret sharing threshold, $1 \leq t \leq n$. 
                 This value specifies the minimum number of shares required for the recovery process.

**Output:** 
 - $\mathbf{s_1, s_2, \dots, s_n}$: A list of $n$ shares. Each share $s_i$ is represented as a tuple 
   $(x_i, y_i)$ consisting of the share index $x_i = i$ (an integer from $1$ to $255$) and the share value $y_i$ 
   (a sequence of $b$ bytes).

Note that typical values for $n$ and $t$ are in the range of $2 \leq t \leq n \leq 255$ .
If $t = 1$, the number of shares required for the recovery is one.
In this case, each share created is just the value being shared.
If $t = n$, all created shares are required for the recovery process.
If, for example, $n = 5$ and $t = 3$, then $5$ shares are created in total. 
and each combination of at least $3$ shares can be used to recover the shared secret.

The process of secret sharing is executed on a byte-per-byte basis, 
i.e., each of the $b$ bytes of the secret $s$ to be shared is processed individually. 
This allows for a simple and efficient implementation using the finite field $\text{GF}(2^8)$ with 256 elements. 
In this field addition and subtraction of two field elements (two bytes) are defined using the bitwise xor operation.
Multiplication of two field elements (again two bytes) is defined using the
AES reducing polynomial $x^8 + x^4 + x^3 + x + 1$. 
For additional background information regarding finite field arithmetic we refer the reader to the
[Wikipedia page on Finite Field Arithmetic](https://en.wikipedia.org/wiki/Finite_field_arithmetic).
The used secret sharing polynomials $f_0(\cdot), f_1(\cdot), \dots, f_{b-1}(\cdot)$ of degree $t - 1$
are evaluated over $\text{GF}(2^8)$:
```math
  f_k(x) = c_0[k] + c_1[k] \cdot x + c_2[k] \cdot x^2 + \dots + c_{t - 1}[k] \cdot x^{t - 1}, \quad 0 \leq k < b.
```
Note that here the values of $c_0, c_1, \dots, c_{t - 1}$ are used to represent lists of coefficients, 
whereas the $k^\textsf{th}$ element of each of the lists of coefficients is used to 
define the secret sharing polynomial for sharing the $k^\textsf{th}$ byte of the secret $s$.

There are two ways to generate each list of coefficients $c_j \mid 0 \leq j < t$ for the $k$ sharing polynomials:
1. Random coefficients (default case)
2. Pseudo-random coefficients (for deterministic secret sharing)

**Random coefficients:**  
In this case all coefficients (despite $c_0$ which holds the secret $s$) are
generated randomly.
```math
    c_j = 
    \begin{cases} 
        s &\text{if } j = 0 \\
        \textsf{random}(b) &\text{if } 0 < j < t
    \end{cases}
```
Hereby, the function $\textsf{random}(b)$ creates a list of $b$ random bytes.
The function MUST use a cryptographically secure source of randomness.

**Pseudo-random coefficients:**  
In this case the coefficinets should be generated deterministically. 
Therefore, pseudorandom value have to be generated as follows: 

```math
    c_j = 
    \begin{cases} 
        s &\text{if } j = 0 \\
        \text{HMAC}_{\text{SHA256}}(s, \text{"secret-sharing-coefficient"} \mid\mid t \mid\mid j \mid\mid \text{session-id})[:b] &\text{if } 0 < j < t
    \end{cases}
```
Here, $[:b]$ is used to denote the first (leftmost) $b$ bytes of the given HMAC. 
The use of $s$  as a secret for the HMAC, in combination with $t$ and $j$ ensures that all bits of the coefficients $c_{t - 1}$ are (pseudo-) random. 
Optionally, a $\text{session-id}$ can be provided to allow sharing the same secret $s$ multiple times with different sets of shares to recover it. 
Therefore, even if a the same secret $s$ is shared multiple times, the coefficients are different under different session ids, but if desired they are equivalent and thus deterministic if the same $\text{session-id}$ is used in multiple invocations.
The session id can be given as string, its UTF-8 encoded form is appended to the byte sequence forming the message for the HMAC function.

The following Python code snippet further illustrates how the lists of coefficients for a particular value of $j$ is generated:
```python
import hashlib
import hmac

list_of_coefficients = hmac.new(
    key=secret,
    msg=b"secret-sharing-coefficient" + bytes([threshold, j]) + (session_id or b""),
    digestmod=hashlib.sha256,
).digest()[: len(secret)]
```

Given this definition of coefficients (and thus of the secret sharing polynomials), 
the $n$ shares $s_1, s_2, ..., s_n$ are computed as follows:
$$s_i = \left( i, f_0(i) \mid\mid f_1(i) \mid\mid \dots \mid\mid f_{b-1}(i) \right), \quad 1 \leq i \leq n$$
Note that a share is a tuple of two values and MUST include the share index $i$ as well as the share value, obtained by evaluating the secret sharing polynomials and concatenating the results.

So far, the only difference to Shamir's original secret sharing is the definition of the coefficients in the pseudo-random case.
In Shamir's original description, all coefficients $c_j \mid 0 < j < t$ are selected at random.
In the pseudo-random case, each list of coefficients is derived from the secret $s$ used as key and additional parameters used as input message for the HMAC-SHA256 function.

To allow users to detect invalid shares during the recovery process additional verification hashes are generated for each share $i$. 
These verification hashes of all shares MAY be printed or transcribed in combination with each individual share in order to verify that the shares of other participants are correct, have not been tampered with, and really belong to the same sharing session during a reconstruction event. 
Using this approach, each party receives one share as well as SHA256 hashes of all $n$ shares. 

To allow to verify any share from linux command line, the verification hash is calculated only using 
SHA256 with the following message syntax:
$$v_i =  \text{SHA256}\big(i \mid\mid \text{":\enspace"} \mid\mid \text{bip39}(s_i) \big)$$

The following Python code illustrates how the verification hash is generated:
```python
import hashlib
verification_hash = hashlib.sha256(f"{share_index_i}: {mnemonic_phrase_of_share_i}").hexdigest()
```

The following is an example of how to check the verfication hash of a given share mnemonic within bash, using
the `sha256sum` tool from the GNU coreutils:
```bash
$ echo -n "3: account blade course knee monitor win chalk twice race cook tray report" | sha256sum
3252fb9ca80f46c928d64ce5f690d76fa848b410049b17cfb637a32f43660def  -
```

## <a name="Recovery"></a>Recovery

This section describes how to reconstruct a secret from a set of $t$ given shares, 
computed with the method specified in [Section Sharing](#Sharing).

**Input:**
 - $\mathbf{ \lbrace (x_1, y_1), (x_2, y_2), \dots, (x_t, y_t) \rbrace }$: 
   A set of at least $t$ distinct shares which should be used to recover a previously shared secret. 
   Each share $(x_j, y_j) \mid 1 \leq j \leq t$ consists of the share index $x_j$ (an integer from $1$ to $255$) and the share value $y_j$ (a sequence of $b$ bytes). 
 - Optionally, the SHA256 hashes of all shares are provided. 

**Output:**
 - $\mathbf{s}$: The recovered secret.


Implementations MUST be able to successfully recover the shared secret $s$, if all given shares are 
*valid* and a *sufficient number* of shares is provided. 
* A share is considered valid, if it was generated according to this specification.
* The number of shares provided is sufficient, if it matches or exceeds the secret sharing threshold $t$ used during the sharing process.

Implementations MUST reject inputs prior to attempting the recovery process, 
and display a corresponding error message in the following cases:
 - The set of shares contains invalid share indices.
   This is the case if $1 \leq x_j \leq 255$ does not hold for some $x_j$, 
   or if the shares indices are not unique within the given set of shares.
 - The set of shares contains invalid share values.
   This is the case if there is a share value of less than $16$ bytes in length,
   or if the share length across the shares is inconsistent (i.e., different) for two or more shares.
 - The set of shares has less elements than specified by $t$. 
 - If verification hashes have been provided, check if all verification hashes are consistent with the provided shares. If one or more verification hashes differ for a given share, the process MUST be aborted and the user must be informed of the error. 

Implementation MAY provide additional functionality to aid with the recovery process in case invalid shares have been provided. Such advanced recovery functionality MUST explicitly be invoked by the user.

If the inputs are successfully validated according to the previously stated plausibility checks, 
implementations attempt to recover the shared secret $s$ from the given set of shares $\{s_i, s_{i'}, \dots, s_{i''}\}$.
For this purpose the underlying secret sharing polynomials $f_k(\cdot)$ are evaluated using the Lagrange interpolation formula: 
```math
  f_k(x) = \sum_{j = 1}^{t} y_j[k] \cdot \ell_j(x), 
  \quad 0 \leq k < b
```
```math
  \ell_j(x) = \prod_{\substack{m = 1 \\ m \not = j}}^{t} \frac{x - x_m}{x_m - x_j}
```

To recover the shared secret $s$ we apply the above formula for $x = 0$ for each of the $k$ shared bytes of the secret:
```math
  s[k] = c_0[k] = f_k(0) = 
    \sum_{j = 1}^{t} y_j[k] 
      \prod_{\substack{m = 1 \\ m \not = j}}^{t} 
        \frac{x_m}{x_m - x_j}, 
  \quad 0 \leq k < b.
```
Which can also be written as,
```math
  s[k] = c_0[k] = f_k(0) = 
    \sum_{j = 1}^{t} y_j[k] 
      \prod_{\substack{m = 1 \\ m \not = j}}^{t} 
        x_m \cdot (x_m - x_j)^{-1}, 
  \quad 0 \leq k < b.
```
Neglecting the notational differences covering the byte-per-byte execution of the process, 
this approach is essentially equal to Shamir's original description. 

## Design and Security Considerations

### Secret size and intended use case

The minimal input size of the secret to be shared with the secret sharing mechanism specified in this document is 
at least $128$ bits. More specifically, only sequences of 16, 20, 24, 28, or 32 bytes are allowed as secret input. 
These are equivalent to the supported BIP39 sizes.

Also this specification MUST NOT be used as basis for an implementation for secret sharing of arbitrary data.
It is instead intended to share cryptographic secrets with a minimum of $128$ bits of entropy. 

### Share verification

The specification defines the secret sharing process on the level of bytes. 
It is intended to be used with encoding schemes such as
[BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) or 
[Bytewords](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-012-bytewords.md) to
encode/decode the in- and outputs. 
These encoding schemes are already designed to add additional safeguards to detect errors, e.g., they include a dedicated checksum and represent bytes as words with a minimum required Damerau-Levenshtein distance etc.
Therefore, no additional checksums and metadata is appended to the raw data output by the secret sharing algorithm in this specification.

Unfortunately, these encoding-level checksums used in mnemonics do not allow for error detection in cases where syntactically correct, but semantically invalid, shares are provided to the recovery process.
These cases include, the following scenarios:

- The recovery process is attempted with a collection of shares generated by two (or more) different secret sharing instances (using different coefficients or secrets). 
- One or more parties deliberately crafts correct-looking shares with invalid share values to prevent the 
  recovering entity to learn the originally shared secret.

In both cases the recovery process would fail silently resulting in a recovered secret 
that is different to the secret originally shared, if no additional countermeasures are implemented.
It is highly desirable to detect, and potentially be able to recover from, these scenarios.
Therefore, this specification includes a verifications hashes.

While there are many different approaches to cover these scenarios, the approach used in this specification achieves a range of desirable properties while minimizing potential drawbacks:
 - No modification to the classical Shamir secret sharing is necessary, as the share generation and recovery process can be used unchanged compared to classical SSS and independent of the verification hashes. 
 - The size of the generated shares does not increase and is equal to the size of the secret to be shared.
 - The verification hashes can be omitted if not desired.  

A drawback is that the verification hashes have to be compared manually.

### Compatibility and separation of concerns

The specification is intentionally designed such that it can be used with different mnemonic schemes and different key derivation schemes building on top of the shared cryptographic keying material. 
This approach follows the separation of concerns principle as 
*generation*, *derivation*, *mnemonic encoding/decoding* and *secret sharing* of cryptographic key material are separate tasks and can thus be defined and implemented separately (see Section [Scope](#Scope) for more details). 
As long as the intermediate formats are well defined, this loose coupling allows for easier replacement and updates of individual components in software stacks and tool chains. 
The document at hand specifies a method for secret sharing of BIP39 mnemonic phrases. 

### Sharing the same secret multiple times

Note that, if shares of multiple different secret sharing invovations with large $n$ values become mixed, this might lead to a situation where it is no longer computationally feasible to perform a brute-force search to find the valid combinations that allow for the reconstruction of the original secrets. 

If random coefficients are used, the resulting shares for each invocation are different and independent from the shares of the other invocations (for the special of case $t = 1$ all generated shares are equal to the secret being shared).
This would ensure that shares from different secret sharing instances cannot (and are by design not supposed to) be combined to successfully recover a secret shared this way.
Therefore, the specified secret sharing scheme in this document MAY safely be invoked multiple times with the same secret as input in the random coefficient setting. 

If a pseudo-random coefficients are used and the same session id has been provided the exactly same shares will be generated. 
If these shares are then distributed differently such that the same entity hols more than $ t $ shares in the end, this party might be able to reconsturct the secret single handelty. 
Therefore, if pseudo-random coefficients are used, it is RECOMMENDED that implementations also generate a unique session ID which represents the individual secret sharing session. 
This secret sharing session identifier SHOULD be written down together with the mnemonic encoding of the share as well as its index. 
This ensures that shares of multiple different sessions do not get mixed and thus confused with each other.
Pseudo-random coefficients allow to verfiy the secert share generation process on different hardware, or over different implementations. 
For successful reconstruction, no additional data is needed to reconstruct the previously shared secret, besides a set of at least $t$ valid shares of the same secret sharing invocation with their associated indices.


### Multi layer / recursive use

The specification implicitly covers the use case of sharing the same secret among different (independent) groups of stakeholders and/or further sharing shares of a shared secret. 

We consider this as an advanced use case, and in contrast to, e.g., 
the [SLIP39](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) proposal, deliberately do not complicate this specification by introducing an additional notation for groups to explicitly capture such use cases.
Yet, our specification transparently allows to re-share the shares for a given secret in a natural way: 
This is simply accomplished by feeding a share, which should be further split up, as secret into the secret sharing procedure.
While special care must be taken to ensure that the way secrets are shared and may later be recombined is noted, our approach in principle allows for an arbitrary number of nested secret sharing layers.


### The use of $\mathbf{GF(2^8)}$
This design performs all secret sharing and recovery computations in the finite field $\text{GF}(2^8)$. 
This allows the specified algorithms to process the data on a byte-per-byte level and simplifies implementations in 
programming languages or on hardware platform with no immediate support for arbitrary precision integer arithmetics.
Using this approach, share indices are restricted to integers from $1$ to $255$.
Thus the maximum number of shares is limited to $255$.
However in practice, we only see this as minor limitation for the indented use case of sharing mnemonic phrases, where human interaction is involved.

## Implementation
The reference implementation of this scheme can be found in the 
[BIP39 Toolkit](https://github.com/de-centralized-systems/bip39toolkit).

For tests and test vectors see [`test`](https://github.com/de-centralized-systems/bip39toolkit/tree/main/tests) directory. 

## References  

 - [BIP39 Toolkit](https://github.com/de-centralized-systems/bip39toolkit), 
   our implementation of this specification using BIP39 as encoding
 - [Shamir's Original Paper "How to share a Secret"](https://dl.acm.org/doi/pdf/10.1145/359168.359176)
 - [Wikipedia Page on Finite Field Arithmetics](https://en.wikipedia.org/wiki/Finite_field_arithmetic)
 - [BIP39 Specification "Mnemonic code for generating deterministic keys"](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
 - [Bytewords Specification "Encoding binary data as English words"](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-012-bytewords.md)
 - [SLIP39 specification](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
 - [BC-SSKR](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-011-sskr.md)
 - [Shamir39](https://iancoleman.io/shamir39/)
 - [BIP93](https://github.com/bitcoin/bips/blob/master/bip-0093.mediawiki)

## Version History

* 2023-06-19
 - Minor revision and polishing for github style markdown
* 2023-05-30
 - Initial draft.
