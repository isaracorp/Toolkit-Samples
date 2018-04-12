# Toolkit-Samples

> The ISARA Radiate Security Solution Suite offers an implementation of
> cryptographic algorithms resistant to quantum computer attacks through a
> lightweight library with a C language interface. This toolkit is the first
> opportunity for customers to start deploying quantum resistant technology in
> a variety of commercial solutions, through drop-in algorithm replacements
> that allow them to build products with an emphasis on quality assurance and
> efficient integration.

For more information about ISARA's quantum resistant solutions, visit
our website: [www.isara.com](https://www.isara.com).

You can also contact us directly at
[quantumsafe@isara.com](mailto:quantumsafe@isara.com).

Copyright &copy; 2016-2018 ISARA Corporation, All Rights Reserved.

## ISARA Radiate Security Solution Suite 1.4 Samples

These samples all require version 1.4 of our toolkit; for more information,
visit [www.isara.com](https://www.isara.com) or contact our
[sales team](mailto:quantumsafe@isara.com).

Each sample demonstrates one part of the toolkit. We use the Dilithium samples
to produce digital signatures of the toolkit's installation packages, for
example.

### System Requirements

Recommended:

* Android 7.0 (Nougat) or newer (API level 24 or higher)
* iOS 10 or newer
* Linux (Ubuntu 16.04 LTS or newer, Debian 9.1 or newer; 64-bit platforms)
* macOS 10.11 or newer
* Windows 10 (64-bit platforms)

Minimum:

* Android 5.0 (Lollipop) or newer (API level 21 or higher)
* iOS 8.1 or newer
* Linux (Ubuntu 14.04 LTS or newer, Debian 8 or newer)
* macOS 10.10 or newer
* Windows 7 or newer (64-bit platforms)

Supported Architectures by OS:

* Android: x86, x86_64, armabi-v7a, arm64-v8a
* iOS: x86, x86_64, armv7, armv7s, arm64
* Linux: x86_64, core2, sandybridge, skylake
* macOS: x86_64, core2, sandybridge, skylake
* Windows: x86_64, core2, sandybridge, skylake

Additional architecture-specific builds can also be created on demand; please
contact ISARA’s [sales team](mailto:quantumsafe@isara.com).

## Samples

Sample code for the ISARA toolkit. We're rearranged the samples so reduce the
number of top-level directories:

* `aead_chacha20_poly1305` - ChaCha20/Poly1305 AEAD encryption and decryption.
* `chacha20` - ChaCha20 encryption and decryption.
* `dilithium` - Dilithium digital signature system.
* `ecdh` - Elliptic curve Diffie-Hellman key exchange.
* `hash` - Hashing using any of our supported hash algorithms.
* `hmac` - Hash-based Message Authentication Codes using any of our supported algorithms.
* `kdf_concatenation` - Tool for deriving keys using the
  [NIST SP 800-56A](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf)
  Alternative 1 Concatenation KDF scheme.
* `kdf_pbkdf2` - Tool for deriving keys using the Password-Based Key Derivation
  Function 2 from IETF's
  [RFC 2898](https://tools.ietf.org/html/rfc2898#appendix-A.2).
* `kdf_rfc5869` - Tool for deriving keys using the HMAC-based
  Extract-and-Expand Key Derivation Function from IETF's
  [RFC 5869](https://tools.ietf.org/html/rfc5869).
* `kyber` - Kyber key-encapsulation mechanism.
* `lms` - Leighton-Micali One Time Signature digital signature scheme.
* `luke` - LUKE (Lattice based Unique Key Establishment) key exchange.
* `mceliece` - McEliece QC-MDPC key-encapsulation mechanism.
* `newhope` - NewHope key exchange.
* `ntruprime` - NTRUPrime key-encapsulation mechanism.
* `poly1305` - Poly1305 message authentication codes.
* `rainbow` - Rainbow digital signature scheme.
* `rng` - Random number generators.
* `sidh` - Supersingular Isogeny Diffie-Hellman key exchange.
* `xmss` - eXtended Merkel Signature System digital signature scheme.

### Building Samples

We've switched to building the samples all at once with `cmake`. You can still
build them separately using the `CMakeLists.txt` found in each directory.

*NOTE*

> Before building the samples, copy one of the CPU-specific versions of the
> toolkit libraries into a `lib` directory. For example, to build the samples
> for Intel Core 2 or better CPUs, copy the contents of `lib_core2` into `lib`.

To build the samples:

1. Install the toolkit somewhere, e.g. `/path/to/toolkitroot/`.
2. `cd` to the sample subdirectory, such as `/path/to/samples/`.
3. Run CMake: `cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkitroot/ .` or
`IQR_TOOLKIT_ROOT=/path/to/toolkitroot cmake .`
4. Run make: `make`

For more details and tool requirements, please refer to the
_[Developer's Guide](https://www.isara.com/toolkit/1.4/doc/guide/guide.html)_
documentation.

The samples use the `IQR_TOOLKIT_ROOT` CMake or environment variable to
determine the location of the toolkit to build against. CMake requires that
environment variables are set on the same line as the CMake command, or are
exported environment variables in order to be read properly.

### Running Samples

See the individual `README.md` files in the sample subdirectories for
instructions on running specific samples.

## License

v1.4 2018-03:

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
