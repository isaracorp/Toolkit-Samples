# ISARA Radiate™ Quantum-Safe Library 3.1 RNG Sample

## Introduction to Random Number Generation

From NIST SP 800-90A Rev. 1:

> There are two fundamentally different strategies for generating random bits.
> One strategy is to produce bits non-deterministically, where every bit of
> output is based on a physical process that is unpredictable; this class of
> random bit generators (RBGs) is commonly known as non-deterministic random bit
> generators (NRBGs). The other strategy is to compute bits deterministically
> using an algorithm; this class of RBGs is known as Deterministic Random Bit
> Generators (DRBGs).
> 
> A DRBG is based on a DRBG mechanism as specified in this Recommendation and
> includes a source of randomness. A DRBG mechanism uses an algorithm (i.e., a
> DRBG algorithm) that produces a sequence of bits from an initial value that is
> determined by a seed that is determined from the output of the randomness
> source. Once the seed is provided and the initial value is determined, the DRBG
> is said to be instantiated and may be used to produce output. Because of the
> deterministic nature of the process, a DRBG is said to produce pseudorandom
> bits, rather than random bits. The seed used to instantiate the DRBG must
> contain sufficient entropy to provide an assurance of randomness. If the seed
> is kept secret, and the algorithm is well designed, the bits output by the DRBG
> will be unpredictable, up to the instantiated security strength of the DRBG.
> 
> The security provided by an RBG that uses a DRBG mechanism is a system
> implementation issue; both the DRBG mechanism and its randomness source must be
> considered when determining whether the RBG is appropriate for use by consuming
> applications.

HMAC-DRBG is built around the use of a SHA2-256, SHA2-384, SHA2-512, SHA3-256,
or SHA3-512 hash function using the HMAC
construction. The toolkit's HMAC-DRBG RNG implementation can be initiated using
any of these hash functions.

## Getting Started

We have created a sample application that demonstrates how to use the
toolkit's HMAC-DRBG RNG implementation.

If the seed and reseed input parameters aren't provided, the sample will use
NIST test vectors to seed and reseed the RNG. To follow the NIST test
specifications, reseeding happens immediately after seeding and the random
data is read in two chunks and both are written to the output file. If the
NIST vectors are used, the second chunk is compared against the NIST expected
data vector.

If the NIST vectors aren't used, the program follows the same flow and the
user-provided data is used to seed and reseed the RNG. Normally the RNG would
not be immediately reseeded but would be reseeded periodically with new entropy.

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

* See `iqr_rng.h` in the toolkit's `include` directory.
* [NIST Special Publication 800-90A Revision 1](http://dx.doi.org/10.6028/NIST.SP.800-90Ar1)
* [SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)

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
