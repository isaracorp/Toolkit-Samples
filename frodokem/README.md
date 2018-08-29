# ISARA Radiate Security Solution Suite 1.5 FrodoKEM Samples
ISARA Corporation <info@isara.com>
v1.5 2018-09: Copyright (C) 2016-2018 ISARA Corporation, All Rights Reserved.

## Introduction Key Encapsulation Mechanisms (KEM)

In general, all KEM schemes follow a similar pattern.

1.  The receiver generates a public and private key pair.
2.  The receiver publishes the public key but keeps the private key secret.
3.  A sender obtains the public key.
4.  That sender uses encapsulate to obtain a ciphertext and shared key.
5.  That sender sends the ciphertext to the receiver.
6.  The receiver obtains the ciphertext.
7.  The receiver uses decapsulate on the ciphertext to obtain the shared key.

The shared key can now be used for symmetric encryption. Note that the key has
already been passed through a Key Derivation Function (KDF) so it is not
necessary to do so again.

Generally speaking, public/private keys only need to be generated once and can
be re-used to create multiple shared secrets. The FrodoKEM KEM follows this
pattern.

## Getting Started

We have created 3 small sample applications that demonstrate how to use the
toolkit's FrodoKEM KEM implementation:

* `frodokem_generate_keys` takes care of step 1.
* `frodokem_encapsulate` takes care of step 4.
* `frodokem_decapsulate` takes care of step 7.

As per https://csrc.nist.gov/projects/post-quantum-cryptography/round-1-submissions
:star: **FrodoKEM:**
FrodoKEM implementation provides both AES and cSHAKE implementations of the
FRODOKEM976 wich provides 150 bits of quantum security.

Here is the simplest way to use the samples:

Build the sample application:

```
$ cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkitroot/ .
$ make
```

Execute `frodokem_generate_keys` using default parameters.

Execution and expected outputs:

```
$ ./frodokem_generate_keys
Running ./frodokem_generate_keys with the following parameters:
    public key file: pub.key
    private key file: priv.key
    variant: AES
The context has been created.
Hash functions have been registered in the context.
RNG object has been created.
FrodoKEM parameter structure has been created.
Creating FrodoKEM key-pair.
FrodoKEM public and private key-pair has been created
Public key has been exported.
Private key has been exported.
Successfully saved pub.key (15632 bytes)
Successfully saved priv.key (31280 bytes)
Public and private keys have been saved to disk.
```

Execute `frodokem_encapsulate` using default parameters.

Execution and expected output:

```
$ ./frodokem_encapsulate
Running ./frodokem_encapsulate with the following parameters:
    public key file: pub.key
    ciphertext file: ciphertext.dat
    shared key file: shared.key
    variant: AES
The context has been created.
RNG object has been created.
FrodoKEM parameter structure has been created.
Successfully loaded pub.key (15632 bytes)
Successfully saved ciphertext.dat (15768 bytes)
Successfully saved shared.key (24 bytes)
FrodoKEM encapsulation completed.
```

Execute `frodokem_decapsulate` using default parameters.

Execution and expected output:

```
$ ./frodokem_decapsulate
Running ./frodokem_decapsulate with the following parameters:
    private key file: priv.key
    ciphertext file: ciphertext.dat
    shared key file: shared.key
    variant: AES
The context has been created.
FrodoKEM parameter structure has been created.
Successfully loaded priv.key (31280 bytes)
Successfully loaded ciphertext.dat (15768 bytes)
Successfully saved shared.key (24 bytes)
FrodoKEM decapsulation completed.
```

### frodokem_generate_key

Generates a new public key and private key and saves them to two separate
files.

Command line format:

```
frodokem_generate_keys [--variant AES|cSHAKE] [--pub <filename>]
  [--priv <filename>]
```

Command line defaults:

```
--variant AES
--pub pub.key
--priv priv.key
```

Command line parameter descriptions:

```
[--variant AES|cSHAKE]
The desired variant.

[--pub <filename>]
<filename> is the name of the file where the public key is to be saved.

[--priv <filename>]
<filename> is the name of the file where the private key is to be saved.
```

### frodokem_encapsulate

Creates and saves a ciphertext and shared key.

Command line format:

```
frodokem_encapsulate [--variant AES|cSHAKE] [--pub <filename>]
  [--ciphertext <filename>] [--shared <filename>]
```

Command line defaults:

```
--variant AES
--pub pub.key
--ciphertext ciphertext.dat
--shared shared.key
```

Command line parameter descriptions:

```
[--variant AES|cSHAKE]
The desired variant. Must be the same as in key generation.

[--pub <filename>]
<filename> is the name of the file where the public key is stored.

[--ciphertext <filename>]
<filename> is the name of the file where the ciphertext is to be saved.

[--shared <filename>]
<filename> is the name of the file where the shared key is to be saved.
```

### frodokem_decapsulate

Decapsulates an encapsulated ciphertext and saves the shared key.

Command line format:

```
frodokem_decapsulate [--variant AES|cSHAKE] [--priv <filename>]
    [--ciphertext <filename>] [--shared <filename>]
```

Command line defaults:

```
--variant AES
--priv priv.key
--ciphertext ciphertext.dat
--shared shared.key
```

Command line parameter descriptions:

```
[--variant AES|cSHAKE]
The desired variant. Must be the same as in key generation.

[--priv <filename>]
<filename> is the name of the file where the private key is stored.

[--ciphertext <filename>]
<filename> is the name of the file where the ciphertext is stored.

[--shared <filename>]
<filename> is the name of the file where the shared key is to be saved.
```

## Further Reading

* See `iqr_frodokem.h` in the toolkit's `include` directory.
* https://csrc.nist.gov/projects/post-quantum-cryptography/round-1-submissions
:star: **FrodoKEM:**

## License

See the `LICENSE` file for details:

> Copyright 2016-2018 ISARA Corporation
> 
> Licensed under the Apache License, Version 2.0 (the "License");
> you may not use this file except in compliance with the License.
> You may obtain a copy of the License at
> 
> http://www.apache.org/licenses/LICENSE-2.0
> 
> Unless required by applicable law or agreed to in writing, software
> distributed under the License is distributed on an "AS IS" BASIS,
> WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
> See the License for the specific language governing permissions and
> limitations under the License.
