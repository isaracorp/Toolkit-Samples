# ISARA Radiate™ Quantum-Safe Library 2.0 Kyber KEM Samples

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
be re-used to create multiple shared secrets. The Kyber KEM follows this
pattern.

## Getting Started

We have created 3 small sample applications that demonstrate how to use the
toolkit's Kyber KEM implementation:

* `kyber_generate_keys` takes care of step 1.
* `kyber_encapsulate` takes care of step 4.
* `kyber_decapsulate` takes care of step 7.

As per [Kyber:](https://eprint.iacr.org/2017/634.pdf)CRYSTALS -- Kyber: a
CCA-secure module-lattice-based KEM, the toolkit's Kyber implementation provides
both 128-bit and 224-bit quantum security.

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

* See `iqr_kyber.h` in the toolkit's `include` directory.
* [Kyber:](https://eprint.iacr.org/2017/634.pdf)CRYSTALS -- Kyber: a CCA-secure
module-lattice-based KEM

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
