# ISARA Radiate Security Solution Suite 1.5 RFC 2898 PBKDF2 Sample
ISARA Corporation <info@isara.com>
v1.5 2018-09: Copyright (C) 2016-2018 ISARA Corporation, All Rights Reserved.

## Introduction to Key Derivation Functions

A key derivation function (or KDF) derives one or more secret keys from a
secret value such as a master key, a password, or a passphrase using a
pseudo-random function.

PBKDF2 (Password-Based Key Derivation Function 2) is specified by the
Internet Engineering Taskforce's
[RFC 2898](https://www.ietf.org/rfc/rfc2898.txt), section A.2.

PBKDF2 uses a pseudorandom function to derive keys. It applies a number
of iterations to the function to increase the cost of deriving a single key,
thereby significantly increasing the cost of a of dictionary attack. The
initial recommended number of iterations was 1000, but this was intended to be
increased over time as CPU speeds increase. Now 1000 iterations would provide
insufficient protection and more iterations should be used. The answer to
"How much more?" is, "We don't know," but
[here's a good read on the subject](http://security.stackexchange.com/a/3993).

Using a salt in the key derivation reduces the ability to use precomputed
hashes for attacks. The standard recommends a salt length of at least 64 bits.

## Getting Started

We have created a sample application that demonstrates how to use the
toolkit's PBKDF2 implementation.

Build the sample application:

```
$ cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkitroot/ .
$ make
```

Execute `kdf_pbkdf2` using default parameters.

Execution and expected outputs:

```
$ ./kdf_pbkdf2
Running ./kdf_pbkdf2 with the following parameters...
    hash algorithm: IQR_HASHALGO_SHA2_256
    password: CorrectHorseBatteryStaple
    salt: DEADBEEF
    iterations: 1000
    key size: 32
    output key file: derived.key

Key has been derived.
Successfully saved derived.key (32 bytes)
Derived key has been saved to disk.
```

## kdf_pbkdf2 Usage Details

Command line format:

```
kdf_pbkdf2 [--hash blake2b-256|blake2b-512|sha2-256|sha2-384|sha2-512|
  sha3-256|sha3-512]
  [--pass { string <password> | file <filename> | none }]
  [--salt { string <salt> | file <filename> | none }]
  [--iter <iterations>] [--keysize <size>] [--keyfile <output_filename>]
```

Command line defaults:

```
--hash sha2-256
--pass string CorrectHorseBatteryStaple
--salt string DEADBEEF
--iter 1000
--keysize 32
--keyfile derived.key
```

Command line parameter descriptions:

```
[--hash blake2b-256|blake2b-512|sha2-256|sha2-384|sha2-512|sha3-256|sha3-512]
The hash algorithm to use.

[--pass string <password>]
Read the <password> from the command line.

[--pass file <filename>]
Read the password from file <filename>. The entire contents of the file will
be read.

[--pass none ]
Don't use a password.

[--salt string <salt>]
Read the <salt> from the command line.

[--salt file <filename>]
Read the salt from file <filename>. The entire contents of the file will
be read.

[--salt none]
Don't use a salt.

[--iter <iterations>]
Number of times to iterate the underlying function used in the key derivation.

[--keysize <size>]
The size of the requested key in bytes.

[--keyfile <output_filename>
<output_filename> is the name of the file where the derived key is to be saved.
```

## Further Reading

* See `iqr_kdf.h` in the toolkit's `include` directory.
* [RFC 2898](https://www.ietf.org/rfc/rfc2898.txt)
* [Choosing the number of iterations](http://security.stackexchange.com/a/3993)
* [Obligatory XKCD reference](https://xkcd.com/936/)

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
