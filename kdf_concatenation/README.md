# ISARA Radiate Security Solution Suite 1.2 KDF Samples
ISARA Corporation <info@isara.com>
v1.2 2017-02: Copyright (C) 2016-2017 ISARA Corporation, All Rights Reserved.

## Introduction to Key Derivation Functions

A key derivation function (or KDF) derives one or more secret keys from a
secret value such as a master key, a password, or a passphrase using a
pseudo-random function.

[NIST SP 800-56A](http://dx.doi.org/10.6028/NIST.SP.800-56Ar2)Alternative 1
Concatenation KDF is specified by NIST.

This KDF uses concatenation and a hash function to derive keys. It takes as
input a shared secret, and optionally application specific information
formatted per the specification.

## Getting Started

We have created a sample application that demonstrates how to use the
toolkit's Concatenation KDF implementation.

Normally the shared secret would be a blob of binary data and would contain
non-printable characters and so couldn't be read in from the command line.
For ease of use in this sample we allow the shared secret to be entered via
the command line, but also have an option to read it from a file in case you
want to use a real world shared secret.

Build the sample application:

```
$ cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkitroot/ .
$ make
```

Execute `kdf_concatenation` using default parameters.

Execution and expected outputs:

```
$ ./kdf_concatenation
Running ./kdf_concatenation with the following parameters...
    hash algorithm: IQR_HASHALGO_SHA2_256
    shared secret: 000102030405060708090a0b0c0d0e0f
    info: ISARA-kdf_concatenation
    key size: 32
    output key file: derived.key

Key has been derived.
Successfully saved derived.key (32 bytes)
Derived key has been saved to disk.
```

## kdf_concatenation Usage Details

Command line format:

```
kdf_concatenation [--hash sha2-256|sha2-512|sha3-256|sha3-512]
    [--secret { string <secret> | file <filename> }]
    [--info { string <info> | file <filename> | none }]
    [--keysize <size>] [--keyfile <output_filename>]
```

Command line defaults:

```
--hash sha2-256
--secret string 000102030405060708090a0b0c0d0e0f
--info string ISARA-kdf_concatenation
--keysize 32
--keyfile derived.key
```

Command line parameter descriptions:

```
[--hash sha2-256|sha2-512|sha3-256|sha3-512]
The hash algorithm to use.

[--secret string <secret>]
Read the shared secret from the command line.

[--secret file <filename>]
Read the shared secret from file <filename>. The entire contents of the file
will be read.

[--info string <salt>]
Read the application specific information from the command line.

[--info file <filename>]
Read the application specific information from file <filename>. The entire
contents of the file will be read.

[--info none]
Don't use any application specific information.

[--keysize <size>]
The size of the requested key in bytes.

[--keyfile <output_filename>
<output_filename> is the name of the file where the derived key will be saved.
```

## Further Reading

* See `iqr_kdf.h` in the toolkit's `include` directory.
* [NIST SP 800-56A](http://dx.doi.org/10.6028/NIST.SP.800-56Ar2)Alternative 1
  Concatenation KDF specification

## License

See the `LICENSE` file for details:

> Copyright 2016-2017 ISARA Corporation
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
