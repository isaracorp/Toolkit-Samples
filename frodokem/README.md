# ISARA Radiate™ Quantum-Safe Library 2.0 FrodoKEM Samples
ISARA Corporation <info@isara.com>
v1.6 2018-12: Copyright © 2016-2019, ISARA Corporation, All Rights Reserved.

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
**FrodoKEM:**
FrodoKEM implementation provides both AES and SHAKE implementations of the
FRODOKEM976 wich provides 150 bits of quantum security.

**NOTE**
Before building the samples, copy one of the CPU-specific versions of the
toolkit libraries into a `lib` directory. For example, to build the samples
for Intel Core 2 or better CPUs, copy the contents of `lib_core2` into `lib`.

The samples use the `IQR_TOOLKIT_ROOT` CMake or environment variable to
determine the location of the toolkit to build against. CMake requires that
environment variables are set on the same line as the CMake command, or are
exported environment variables in order to be read properly. If
`IQR_TOOLKIT_ROOT` is a relative path, it must be relative to the directory
where you're running the `cmake` command.

Assuming you've got the Toolkit installed in `/path/to/toolkit`, build the
sample application in a `build` directory:

```
$ mkdir build
$ cd build
$ cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkit/ ..
$ make
```

Execute the samples with no arguments to use the default parameters, or use
`--help` to list the available options.

## Further Reading

* See `iqr_frodokem.h` in the toolkit's `include` directory.
* https://csrc.nist.gov/projects/post-quantum-cryptography/round-1-submissions
**FrodoKEM:**

## License

See the `LICENSE` file for details:

> Copyright © 2016-2019, ISARA Corporation
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

### Trademarks

ISARA Radiate™ is a trademark of ISARA Corporation.
