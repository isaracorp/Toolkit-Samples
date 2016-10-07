# ISARA Toolkit 1.0 KDF Samples
ISARA Corporation <info@isara.com>
v1.0, September 2016: Copyright (C) 2016 ISARA Corporation, All Rights Reserved.

## Introduction to Key Derivation Functions

A key derivation function (or KDF) derives one or more secret keys from a
secret value such as a master key, a password, or a passphrase using a
pseudo-random function.

HMAC-based Extract-and-Expand Key Derivation Function is specified by the
Internet Engineering Taskforce's
[RFC 5869](https://tools.ietf.org/html/rfc5869).

This KDF uses a HMAC function to derive keys. It takes as input some initial
keying material (IKM), and optionally a salt value and application-specific
information.

## Getting Started

We have created a sample application that demonstrates how to use the IQR
Toolkit's RFC 5869 HKDF implementation.

Normally the IKM would be a blob of binary data and would contain non-printable
characters and so couldn't be read in from the command line. For ease of use
in this sample we allow the IKM to be entered via the command line, but also
have an option to read the IKM from a file in case you want to use some real
world IKM.

Build the sample application:

```
$ cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkitroot/ .
$ make
```

Execute `kdf_rfc5869` using default parameters.

Execution and expected outputs:

```
$ ./kdf_rfc5869
Running ./kdf_rfc5869 with the following parameters...
    hash algorithm: IQR_HASHALGO_SHA2_256
    salt: DEADBEEF
    IKM: 000102030405060708090a0b0c0d0e0f
    info: ISARA-kdf_rfc5869
    key size: 32
    output key file: derived.key

Key has been derived.
Successfully saved derived.key (32 bytes)
Derived key has been saved to disk.
```

## kdf_rfc5869 Usage Details

Command line format:

```
kdf_rfc5869 [--hash sha2-256|sha2-512|sha3-256|sha3-512]
    [--salt { string <salt> | file <filename> | none }]
    [--ikm { string <ikm> | file <filename> }]
    [--info { string <info> | file <filename> | none }]
    [--keysize <size>] [--keyfile <output_filename>]
```

Command line defaults:

```
--hash sha2-256
--salt string DEADBEEF
--ikm string 000102030405060708090a0b0c0d0e0f
--info string ISARA-kdf_rfc5869
--keysize 32
--keyfile derived.key
```

Command line parameter descriptions:

```
:star: ** --hash sha2-256|sha2-512|sha3-256|sha3-512 **
The hash algorithm to use.

:star: ** --salt string <salt> **
Read the <salt> from the command line.

:star: ** --salt file <filename> **
Read the salt from file <filename>. The entire contents of the file will
be read.

:star: ** --salt none **
Don't use a salt.

:star: ** --ikm string <ikm> **
Read the initial keying material from the command line.

:star: ** --ikm file <filename> **
Read the initial keying material from file <filename>. The entire contents of
the file will be read.

:star: ** --info string <info> **
Read the application specific information from the command line.

:star: ** --info file <filename> **
Read the application specific information from file <filename>. The entire
contents of the file will be read.

:star: ** --info none **
Don't use any application specific information.

:star: ** --keysize <size> **
The size of the requested key in bytes.

:star: ** --keyfile <output_filename> **
<output_filename> is the name of the file where the derived key is to be saved.
```

## Further Reading

* See `iqr_kdf.h` in the IQR Toolkit's `include` directory.
* [RFC 5869](https://tools.ietf.org/html/rfc5869)

## License

See the `LICENSE` file for details:

> Copyright 2016 ISARA Corporation
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
