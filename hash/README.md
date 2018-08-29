# ISARA Radiate Security Solution Suite 1.5 Hash Sample
ISARA Corporation <info@isara.com>
v1.5 2018-09: Copyright (C) 2016-2018 ISARA Corporation, All Rights Reserved.

## Introduction to Hashing Algorithms

Hashing algorithms are one-way functions that take data as input and return
a small fixed-sized buffer of data.  The one-way property means that given the
input and output of the hashing algorithm it would be difficult to create a
different input that would get the hashing algorithm to produce the exact same
output.

SHA2-256, SHA2-384, SHA2-512, SHA3-256 and SHA3-512 are commonly used hashing
functions.

## Getting Started

We have created a small sample application that demonstrates how to use the
toolkit's hash implementation:

Here is the simplest way to use the sample:

Create a digital message and save it to a file called `message.dat`. For
example, on a lark, we used Project Gutenberg's Alice's Adventures in
Wonderland by Lewis Carroll. (It can be freely obtained from
[Project Gutenberg](http://www.gutenberg.org/ebooks/11.txt.utf-8).)
We downloaded the plaintext version and saved it as `message.dat` in the same
directory that contained the compiled executable of the sample.

Build the sample application:

```
$ cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkitroot/ .
$ make
```

Execute `hash` using default parameters.

Execution and expected outputs:

```
 $ ./hash
Running ./hash with the following parameters...
    hash: IQR_HASHALGO_SHA2_512
    message data file: message.dat

Successfully loaded message.dat (167518 bytes)
Message hashes to:
35b01d539a785400c8f9ebe140415b251106251af7a3426ccafa031b9492c2ff
e4e02a210ac70fff4facf5a3351bc2df93e815e75ed19b161d385980fc0a5b8b
```

## hash Usage Details

Generates a SHA2-256, SHA2-384, SHA2-512, SHA3-256, SHA3-512, BLAKE2b-256, or
BLAKE2b-512 hash of a message.

Command line format:

```
hash
  [--hash sha2-256|sha2-384|sha2-512|sha3-256|sha3-512|blake2b-256|blake2b-512]
  [--salt <filename>] [--message <filename>]
```

Command line defaults:

```
--hash sha2-512
--message message.dat
```

Command line parameter descriptions:

```
[--hash sha2-256|sha2-384|sha2-512|sha3-256|sha3-512|blake2b-256|blake2b-512]
Which hashing algorithm to use. One of SHA2-256, SHA2-384, SHA2-512, SHA3-256,
SHA3-512, BLAKE2b-256 or BLAKE2b-512.

[--salt <filename>]
<filename> contains the random salt to apply to the hash.

[--message <filename>]
<filename> contains the message to be hashed.
```

Note that the `--salt` must have at least 16 bytes of data, if specified.

## Further Reading

* See `iqr_hash.h` in the toolkit's `include` directory.
* [FIPS 180 - SHA2](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
* [FIPS 202 - SHA3](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
* [Blake2](https://blake2.net/blake2.pdf)

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
