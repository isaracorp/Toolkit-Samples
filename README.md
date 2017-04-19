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

You can also contact us directly at [info@isara.com](mailto:info@isara.com).

Copyright &copy; 2016-2017 ISARA Corporation, All Rights Reserved.

## ISARA Radiate Security Solution Suite 1.2 Samples

These samples all require version 1.2 of our toolkit; for more information,
visit [www.isara.com](https://www.isara.com) or contact our
[sales team](mailto:sales@isara.com).

Each sample demonstrates one part of the toolkit. We use the LMS samples to
produce digital signatures of the toolkit's installation packages, for example.

### System Requirements

These samples have been tested on:

* 64-bit FreeBSD 10
* 64-bit Mac OS X 10.11, Mac OS X 10.12
* 64-bit Ubuntu 14.04, Ubuntu 16.04, 64-bit Arch
* 64-bit Windows 10

For more information about the Toolkit's system requirements and supported
platforms, please read the [documentation](https://www.isara.com/radiate/1/).

## Samples

Sample code for the ISARA toolkit.

* `aead_chacha20_poly1305_decrypt` - Tool for performing ChaCha20/Poly1305 AEAD
   decryption.
* `aead_chacha20_poly1305_encrypt` - Tool for performing ChaCha20/Poly1305 AEAD
   encryption.
* `chacha20_decrypt` - Tool for performing ChaCha20 decryption.
* `chacha20_encrypt` - Tool for performing ChaCha20 encryption.
* `hash` - Tool for hashing messages with SHA-256 or SHA-512.
* `hmac` - Tool for creating HMAC tags.
* `kdf_concatenation` - Tool for deriving keys using the NIST SP 800-56A
  Alternative 1 Concatenation KDF scheme.
* `kdf_pbdkf2` - Tool for deriving keys using the Password-Based Key Derivation
  Function 2 from IETF's RFC 2898.
* `kdf_rfc58691` - Tool for deriving keys using the HMAC-based
  Extract-and-Expand Key Derivation Function from IETF's RFC 5869.
* `lms_generate_keys` - Tool for generating LMS keys.
* `lms_sign` - Tool for signing with LMS keys.
* `lms_verify` - Tool for verifying an LMS signature.
* `luke` - Demo of the LUKE (lattice) key exchange scheme.
* `mceliece_decrypt` - Tool for decryption with McEliece QC-MDPC keys.
* `mceliece_encrypt` - Tool for encryption with McEliece QC-MDPC keys.
* `mceliece_generate_keys` - Tool for generating McEliece QC-MDPC keys.
* `newhope` - Demo of the NewHope (lattice) key exchange scheme.
* `poly1305` - Tool for creating Poly1305 MAC tags.
* `rng` - Demo of HMAC-DRBG random number generation.

### Building Samples

Each sample builds independently of the toolkit, and each other.
The samples use the `IQR_TOOLKIT_ROOT` CMake or environment variable to
determine the location of the toolkit to build against. CMake requires that
environment variables are set on the same line as the CMake command, or are
exported environment variables in order to be read properly. If
`IQR_TOOLKIT_ROOT` is a relative path, it must be relative to the individual
sample subdirectories.

1. Install the toolkit somewhere, e.g. `/path/to/toolkitroot/`.
2. `cd` to a sample subdirectory, such as `samples/lms_generate_keys`.
3. Run CMake: `cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkitroot/ .` or
`IQR_TOOLKIT_ROOT=/path/to/toolkitroot cmake .`
4. Run make: `make`

### Running Samples

See the individual `README.html` files in the sample subdirectories for
instructions on running specific samples.

## License

v1.2, April 2017:

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
