# ISARA Radiate Security Solution Suite 1.4 McEliece QC-MDPC KEM Samples
ISARA Corporation <info@isara.com>
v1.4 2018-03: Copyright (C) 2016-2018 ISARA Corporation, All Rights Reserved.

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

Generally speaking, public/private keys only need to be generated once.
The McEliece cryptosystem follows this pattern.

## Getting Started

We have created 3 small sample applications that demonstrate how to use the
toolkit's McEliece QC-MDPC KEM implementation:

* `mceliece_generate_keys` takes care of step 1.
* `mceliece_encapsulate` takes care of step 4.
* `mceliece_decapsulate` takes care of step 7.

As per [MDPC-McEliece:](https://eprint.iacr.org/2012/409.pdf)New McEliece
Variants from Moderate Density Parity-Check Codes, the toolkit's
McEliece QC-MDPC implementation uses key size 32771 (bits) which provides
256-bit classical security and 128-bit quantum security.

Here is the simplest way to use the samples:

Build the sample application:

```
$ cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkitroot/ .
$ make
```

Execute `mceliece_generate_keys` using default parameters.

Execution and expected outputs:

```
$ ./mceliece_generate_keys
Running ./mceliece_generate_keys with the following parameters:
    public key file: pub.key
    private key file: priv.key
    key size: 32771 bits
The global context has been created.
Hash functions have been registered in the global context.
RNG object has been created.
McEliece QC-MDPC parameter structure has been created.
McEliece QC-MDPC public and private key-pair has been created
Public key has been exported.
Private key has been exported.
Successfully saved pub.key (4097 bytes)
Successfully saved priv.key (8193 bytes)
Public and private keys have been saved to disk.
```

Execute `mceliece_encapsulate` using default parameters.

Execution and expected output:

```
$ ./mceliece_encapsulate
Running ./mceliece_encapsulate with the following parameters:
    public key file: pub.key
    ciphertext file: ciphertext.dat
    shared key file: shared.key
    key size: 32771 bits
The context has been created.
Hash functions have been registered in the context.
RNG object has been created.
McEliece QC-MDPC parameter structure has been created.
Successfully loaded pub.key (4097 bytes)
Successfully saved ciphertext.dat (8225 bytes)
Successfully saved shared.key (32 bytes)
McEliece QC-MDPC encapsulation completed.
```

Execute `mceliece_decapsulate` using default parameters.

Execution and expected output:

```
$ ./mceliece_decapsulate
Running ./mceliece_decapsulate with the following parameters:
    private key file: priv.key
    ciphertext file: ciphertext.dat
    shared key file: shared.key
    key size: 32771 bits
The context has been created.
Hash functions have been registered in the context.
McEliece QC-MDPC parameter structure has been created.
Successfully loaded priv.key (8193 bytes)
Successfully loaded ciphertext.dat (8225 bytes)
Successfully saved shared.key (32 bytes)
McEliece QC-MDPC decapsulation completed.
```

### mceliece_generate_key

Generates a new public key and private key and saves them to two separate
files.

Command line format:

```
mceliece_generate_keys [--pub <filename>] [--priv <filename>]
```

Command line defaults:

```
--pub pub.key
--priv priv.key
```

Command line parameter descriptions:

```
[--pub <filename>]
<filename> is the name of the file where the public key is to be saved.

[--priv <filename>]
<filename> is the name of the file where the private key is to be saved.
```

### mceliece_encapsulate

Creates and saves a ciphertext and shared key.

Command line format:

```
mceliece_encapsulate [--pub <filename>] [--ciphertext <filename>]
 [--shared <filename>]

```

Command line defaults:

```
--pub pub.key
--ciphertext ciphertext.dat
--shared shared.key
```

Command line parameter descriptions:

```
[--pub <filename>]
<filename> is the name of the file where the public key is stored.

[--ciphertext <filename>]
<filename> is the name of the file where the ciphertext is to be saved.

[--shared <filename>]
<filename> is the name of the file where the shared key is to be saved.
```

### mceliece_decapsulate

Decapsulates an encapsulated ciphertext and saves the shared key.

Command line format:

```
mceliece_decapsulate [--priv <filename>] [--ciphertext <filename>]
 [--shared <filename>]
```

Command line defaults:

```
--priv priv.key
--ciphertext ciphertext.dat
--shared shared.key
```

Command line parameter descriptions:

```
[--priv <filename>]
<filename> is the name of the file where the private key is stored.

[--ciphertext <filename>]
<filename> is the name of the file where the ciphertext is stored.

[--shared <filename>]
<filename> is the name of the file where the shared key is to be saved.
```

## Further Reading

* See `iqr_mceliece.h` in the toolkit's `include` directory.
* [MDPC-McEliece:](https://eprint.iacr.org/2012/409.pdf)New McEliece Variants
  from Moderate Density Parity-Check Codes

TODO(Alex P.) T2002 - Add a reference for the KEM here.

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
