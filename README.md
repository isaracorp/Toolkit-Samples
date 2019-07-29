# ISARA Radiate™ Quantum-safe Library 2.0 Samples

## Samples

Sample code for the toolkit.  Each directory has one or more self-contained
programs inside demonstrating how to use the toolkit for a specific purpose:

* `aead_chacha20_poly1305` &mdash; Encrypt/decrypt using ChaCha20/Poly1305 for
  authenticated encryption.
* `chacha20` &mdash; Encrypt/decrypt using ChaCha20.
* `classicmceliece` &mdash; Generate keys, encapsulate and decapsulate data
  using the Classic McEliece KEM.
* `dilithium` &mdash; Generate Dilithium keys, sign a file's data with a
  Dilithium key, and verify a Dilithium signature.
* `frododh` &mdash; Agree on a shared secret using Frodo, a relative of the
  NewHope scheme.
* `frodokem` &mdsh; Generate keys, encapsulate and decapsulate data using
  FrodoKEM.
* `hash` &mdash; Hash a file's data using SHA2-256, SHA2-384, SHA2-512,
  SHA3-256, or SHA3-512.
* `hmac` &mdash; Get the HMAC tag for a file's data using any of the available
  hash algorithms.
* `hss` &mdash; Generate keys, sign a file's data, detach signatures from a
  private key's state, and verify a signature using the HSS algorithm.
* `kdf_concatenation`, `kdf_pbkdf2`, and `kdf_rfc5869` &mdash; Derive a key
  (some pseudorandom data) using the specified key derivation function.
* `kyber` &mdash; Generate keys, encapsulate and decapsulate data using
  Kyber.
* `newhopedh` &mdash; Agree on a shared secret using the NewHopeDH scheme.
* `ntruprime` &mdash; Generate keys, encapsulate and decapsulate data
  using NTRUPrime.
* `poly1305` &mdash; Get the Poly1305 tag for a file's data.
* `rainbow` &mdash; Generate keys, sign a file's data, and verify a signature
  using the Rainbow algorithm.
* `rng` &mdash; Generate pseudorandom bytes using HMAC-DRBG.
* `samwise` &mdash; Agree on a shared secret using an optimized variant of
  Frodo.
* `sidh` &mdash; Agree on a shared secret using Supersingular Isogeny
  Diffie-Hellman.
* `sike` &mdash; Generate keys, encapsulate and decapsulate data using
  Supersingular Isogeny Key Encapsulation.
* `sphincs` &mdash; Generate keys, sign a file's data, and verify a signature
  using the SPHINCS+ algorithm.
* `version` &mdash; Display the library's version information.
* `xmss` &mdash; Generate keys, sign a file's data, detach signatures from a
  private key's state, and verify a signature using the XMSS algorithm.
* `xmssmt` &mdash; Generate keys, sign a file's data, detach signatures from a
  private key's state, and verify a signature using the XMSS<sup>MT</sup> algorithm.

### Building Samples

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

1. Install the toolkit somewhere, e.g. `/path/to/toolkit/`.
2. `cd` to the `samples` directory, such as `/path/to/toolkit/samples/`.
3. Use `mkdir` to make a `build` directory; `cd` into the `build` directory.
3. Run CMake: `cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkit/ ..` or
   `IQR_TOOLKIT_ROOT=/path/to/toolkit cmake ..` The `..` in there refers to
   the parent of your `build` directory, so it'll pick up the `CMakeLists.txt`
   in the main `samples` directory.
4. Run make: `make`

This will build all of the samples in individual directories under the `build`
directory.

**NOTE**
Don't build the samples on macOS using `gcc` 8, they will crash before `main()`
due to a problem with `-fstack-protector-all`. Use `clang` to produce Mac
binaries.

To build individual samples:

1. Install the toolkit somewhere, e.g. `/path/to/toolkit/`.
2. `cd` to the specific `samples` directory, such as
   `/path/to/toolkit/samples/hash`.
3. Use `mkdir` to make a `build` directory; `cd` into the `build` directory.
3. Run CMake: `cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkit/ ..` or
   `IQR_TOOLKIT_ROOT=/path/to/toolkit cmake ..` The `..` in there refers to
   the parent of your `build` directory, so it'll pick up the `CMakeLists.txt`
   in the specific `samples` directory (the one in `hash` in this case).
4. Run make: `make`

This will build the specific sample in the `build` directory.

### Running Samples

See individual `README.html` files in the sample subdirectories for instructions
on running specific samples.

Execute the samples with no arguments to use the default parameters, or use
`--help` to list the available options.

### Security Issues

For information about reporting security issues, please read the
[SECURITY](https://github.com/isaracorp/Toolkit-Samples/blob/master/SECURITY.md)
document.

## Documentation

You can read the toolkit documentation online at ISARA's website:

* [Developer's Guide](https://www.isara.com/toolkit/2/doc/guide/guide.html)
* [Library Reference](https://www.isara.com/toolkit/2/doc/library/index.html)
* [README](https://www.isara.com/toolkit/2/README.html)

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
