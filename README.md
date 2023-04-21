# ISARA Radiate™ Quantum-Safe Library 3.1 Samples

## Samples

Sample code for the toolkit. Each directory has one or more self-contained
programs inside demonstrating how to use the toolkit for a specific purpose:

* `aead_chacha20_poly1305` &mdash; Encrypt/decrypt using ChaCha20/Poly1305 for
  authenticated encryption.
* `chacha20` &mdash; Encrypt/decrypt using ChaCha20.
* `classicmceliece` &mdash; Generate keys, encapsulate and decapsulate data
  using the Classic McEliece KEM.
* `common` &mdash; A small library of functions common to the samples.
* `dilithium` &mdash; Generate Dilithium keys, sign a file's data with a
  Dilithium key, and verify a Dilithium signature.
* `hash` &mdash; Hash a file's data using SHA2-256, SHA2-384, SHA2-512,
  SHA3-256, or SHA3-512.
* `hss` &mdash; Generate keys, sign a file's data, detach signatures from a
  private key's state, and verify a signature using the HSS algorithm.
* `integration` &mdash; Integrating the toolkit with other software.
* `kdf` &mdash; Derive a key (some pseudorandom data) using the specified key
  derivation function.
* `kyber` &mdash; Generate keys, encapsulate and decapsulate data using
  Kyber.
* `mac` &mdash; Generate a message authentication code using the specified MAC
  algorithm.
* `rng` &mdash; Generate pseudorandom bytes using HMAC-DRBG.
* `sphincs` &mdash; Generate keys, sign a file's data, and verify a signature
  using the SPHINCS+ algorithm.
* `version` &mdash; Display the library's version information.
* `VisualStudio` &mdash; Visual Studio solution and project files.
* `xmss` &mdash; Generate keys, sign a file's data, detach signatures from a
  private key's state, and verify a signature using the XMSS algorithm.

The `integration` directory has samples showing how to integrate external
implementations with the toolkit. These samples may have external dependencies
on specific software such as OpenSSL, or specific operating system features such
as having a `/dev/urandom` device available.

* `integration/hash-openssl` - Demonstrates using OpenSSL's SHA-256 and SHA-512
  with the toolkit's hash API.
* `integration/rng-cng` - Demonstrates using the Windows Cryptography API:
  Next Generation (CNG) with the toolkit's random number generator API.
* `integration/rng-urandom` - Demonstrates using `/dev/urandom` with the
  toolkit's random number generator API.

### Building Samples

For an evaluation copy of the ISARA Radiate™ Quantum-Safe Library, please
contact our [sales team](mailto:sales@isara.com?subject=Radiate%20evaluation).

**NOTE**
In addition to your platform's usual development tools, you'll need a recent
version of `cmake` (version 3.7 or newer): https://cmake.org/ For most systems,
you can use your platform's normal package tools to install it, but you may
need to build an up-to-date version. Binaries are also available on the CMake
website.

The samples use the `IQR_TOOLKIT_ROOT` CMake or environment variable to
determine the location of the toolkit to build against. CMake requires that
environment variables are set on the same line as the CMake command, or are
exported environment variables in order to be read properly. If
`IQR_TOOLKIT_ROOT` is a relative path, it must be relative to the directory
where you're running the `cmake` command.

1. Install the toolkit somewhere, e.g. `/path/to/toolkit/`.
2. `cd` to the `samples` directory, such as `/path/to/toolkit/samples/`.
3. Use `mkdir` to make a `build` directory; `cd` into the `build` directory.
4. Run CMake: `cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkit/ ..` or
   `IQR_TOOLKIT_ROOT=/path/to/toolkit cmake ..` The `..` in there refers to
   the parent of your `build` directory, so it'll pick up the `CMakeLists.txt`
   in the main `samples` directory.
5. Run make: `make`

This will build all of the samples in individual directories under the `build`
directory.

Use `-DSTATIC=ON` to link against the static toolkit library instead of the
default shared library.

**NOTE**
Don't build the samples on macOS using `gcc` 8, they will crash before `main()`
due to a problem with `-fstack-protector-all`. Use `clang` to produce Mac
binaries.

Windows developers can also use Visual Studio to build the samples, using the
solution and project files found in `VisualStudio`.

To build individual samples:

1. Install the toolkit somewhere, e.g. `/path/to/toolkit/`.
2. `cd` to the specific `samples` directory, such as
   `/path/to/toolkit/samples/hash`.
3. Use `mkdir` to make a `build` directory; `cd` into the `build` directory.
4. Run CMake: `cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkit/ ..` or
   `IQR_TOOLKIT_ROOT=/path/to/toolkit cmake ..` The `..` in there refers to
   the parent of your `build` directory, so it'll pick up the `CMakeLists.txt`
   in the specific `samples` directory (the one in `hash` in this case).
5. Run make: `make`

This will build the specific sample in the `build` directory.

### Running Samples

See individual `README.md` files in the sample subdirectories for instructions
on running specific samples.

Execute the samples with no arguments to use the default parameters, or use
`--help` to list the available options.

### Security Issues

For information about reporting security issues, please read the
[SECURITY](https://github.com/isaracorp/Toolkit-Samples/blob/master/SECURITY.md)
document.

## Documentation

You can read the toolkit documentation online at ISARA's website:

* [Developer's Guide](https://www.isara.com/toolkit/3.1/doc/guide/guide.html)
* [Library Reference](https://www.isara.com/toolkit/3.1/doc/library/index.html)
* [README](https://www.isara.com/toolkit/3.1/README.html)

## License

See the `LICENSE` file for details:

> Copyright © 2016-2023, ISARA Corporation
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
