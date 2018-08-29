# ISARA Radiate Security Solution Suite 1.5 SIKE KEM Samples
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
be re-used to create multiple shared secrets. The SIKE cryptosystem follows
this pattern.

## Getting Started

We have created 3 small sample applications that demonstrate how to use the
toolkit's SIKE KEM implementation:

* `sike_generate_keys` takes care of step 1.
* `sike_encapsulate` takes care of step 4.
* `sike_decapsulate` takes care of step 7.

As per SIKE NIST submission.

Here is the simplest way to use the samples:

Build the sample application:

```
$ cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkitroot/ .
$ make
```

Execute `sike_generate_keys` using default parameters.

Execution and expected outputs:

```
$ ./sike_generate_keys
Running ./sike_generate_keys with the following parameters:
    variant: p751
    public key file: pub.key
    private key file: priv.key
The global context has been created.
RNG object has been created.
SIKE parameter structure has been created.
SIKE public and private key-pair has been created
Public key has been exported.
Private key has been exported.
Successfully saved pub.key (1088 bytes)
Successfully saved priv.key (2656 bytes)
Public and private keys have been saved to disk.
```

Execute `sike_encapsulate` using default parameters.

Execution and expected output:

```
$ ./sike_encapsulate
Running ./sike_encapsulate with the following parameters:
    variant: p751
    public key file: pub.key
    ciphertext file: ciphertext.dat
    shared key file: shared.key
The context has been created.
RNG object has been created.
SIKE parameter structure has been created.
Successfully loaded pub.key (1088 bytes)
Successfully saved ciphertext.dat (1184 bytes)
Successfully saved shared.key (32 bytes)
SIKE encapsulation completed.
```

Execute `sike_decapsulate` using default parameters.

Execution and expected output:

```
$ ./sike_decapsulate
Running ./sike_decapsulate with the following parameters:
    variant: p751
    private key file: priv.key
    ciphertext file: ciphertext.dat
    shared key file: shared.key
The context has been created.
SIKE parameter structure has been created.
Successfully loaded priv.key (2656 bytes)
Successfully loaded ciphertext.dat (1184 bytes)
Successfully saved shared.key (32 bytes)
SIKE decapsulation completed.
```

### sike_generate_key

Generates a new public key and private key and saves them to two separate
files.

Command line format:

```
sike_generate_keys [--variant p503|p751] [--pub <filename>] [--priv <filename>]
```

Command line defaults:

```
--variant p751
--pub pub.key
--priv priv.key
```

Command line parameter descriptions:

```
[--variant p503|p751]
The desired variant.

[--pub <filename>]
<filename> is the name of the file where the public key is to be saved.

[--priv <filename>]
<filename> is the name of the file where the private key is to be saved.
```

### sike_encapsulate

Creates and saves a ciphertext and shared key.

Command line format:

```
sike_encapsulate [--variant p503|p751] [--pub <filename>]
    [--ciphertext <filename>] [--shared <filename>]
```

Command line defaults:

```
--variant: p751
--pub pub.key
--ciphertext ciphertext.dat
--shared shared.key
```

Command line parameter descriptions:

```
[--variant p503|p751]
The desired variant. Must be the same as in key generation.

[--pub <filename>]
<filename> is the name of the file where the public key is stored.

[--ciphertext <filename>]
<filename> is the name of the file where the ciphertext is to be saved.

[--shared <filename>]
<filename> is the name of the file where the shared key is to be saved.
```

### sike_decapsulate

Decapsulates an encapsulated ciphertext and saves the shared key.

Command line format:

```
sike_decapsulate [--variant p503|p751] [--priv <filename>]
    [--ciphertext <filename>] [--shared <filename>]
```

Command line defaults:

```
--variant: p751
--priv priv.key
--ciphertext ciphertext.dat
--shared shared.key
```

Command line parameter descriptions:

```
[--variant p503|p751]
The desired variant level. Must be the same as in key generation.

[--priv <filename>]
<filename> is the name of the file where the private key is stored.

[--ciphertext <filename>]
<filename> is the name of the file where the ciphertext is stored.

[--shared <filename>]
<filename> is the name of the file where the shared key is to be saved.
```

## Further Reading

* See `iqr_sike.h` in the toolkit's `include` directory.

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