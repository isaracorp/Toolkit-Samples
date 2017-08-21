# ISARA Radiate Security Solution Suite 1.3 NTRUPrime KEM Samples
ISARA Corporation <info@isara.com>
v1.3 2017-09: Copyright (C) 2017 ISARA Corporation, All Rights Reserved.

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
be re-used multiple times.
The NTRUPrime cryptosystem follows this pattern.

## Getting Started

We have created 3 small sample applications that demonstrate how to use the
toolkit's NTRUPrime KEM implementation:

* `ntruprime_generate_keys` takes care of step 1.
* `ntruprime_encapsulate` takes care of step 4.
* `ntruprime_decapsulate` takes care of step 7.

As per [NTRU Prime](https://eprint.iacr.org/2016/461).
The toolkit's NTRUPrime implementation uses the parameter set recommended in
the above paper for 128-bit quantum security.

Here is the simplest way to use the samples:

Build the sample application:

```
$ cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkitroot/ .
$ make
```

Execute `ntruprime_generate_keys` using default parameters.

Execution and expected outputs:

```
$ ./ntruprime_generate_keys
Running ./ntruprime_generate_keys with the following parameters:
    public key file: pub.key
    private key file: priv.key
The context has been created.
Hash functions have been registered in the context.
RNG object has been created.
NTRUPrime parameter structure has been created.
Creating NTRUPrime key-pair.
NTRUPrime public and private key-pair has been created
Public key has been exported.
Private key has been exported.
Successfully saved pub.key (1235 bytes)
Successfully saved priv.key (4434 bytes)
Public and private keys have been saved to disk.
```

Execute `ntruprime_encapsulate` using default parameters.

Execution and expected output:

```
$ ./ntruprime_encapsulate
Running ./ntruprime_encapsulate with the following parameters:
    public key file: pub.key
    ciphertext file: ciphertext.dat
    shared key file: shared.key
The context has been created.
Hash functions have been registered in the context.
RNG object has been created.
NTRUPrime parameter structure has been created.
Successfully loaded pub.key (1235 bytes)
Successfully saved ciphertext.dat (1267 bytes)
Successfully saved shared.key (32 bytes)
NTRUPrime encapsulation completed.
```

Execute `ntruprime_decapsulate` using default parameters.

Execution and expected output:

```
$ ./ntruprime_decapsulate
Running ./ntruprime_decapsulate with the following parameters:
    private key file: priv.key
    ciphertext file: ciphertext.dat
    shared key file: shared.key
The context has been created.
Hash functions have been registered in the context.
NTRUPrime parameter structure has been created.
Successfully loaded priv.key (4434 bytes)
Successfully loaded ciphertext.dat (1267 bytes)
Successfully saved shared.key (32 bytes)
NTRUPrime decapsulation completed.
```

### ntruprime_generate_key

Generates a new public key and private key and saves them to two separate
files.

Command line format:

```
ntruprime_generate_keys [--pub <filename>] [--priv <filename>]
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

### ntruprime_encapsulate

Creates and saves a ciphertext and shared key.

Command line format:

```
ntruprime_encapsulate [--pub <filename>] [--ciphertext <filename>]
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

### ntruprime_decapsulate

Decapsulates an encapsulated ciphertext and saves the shared key.

Command line format:

```
ntruprime_decapsulate [--priv <filename>] [--ciphertext <filename>]
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

* See `iqr_ntruprime.h` in the toolkit's `include` directory.
* [NTRU Prime](https://eprint.iacr.org/2016/461).

## License

See the `LICENSE` file for details:

> Copyright 2017 ISARA Corporation
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
