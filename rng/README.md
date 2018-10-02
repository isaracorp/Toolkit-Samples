# ISARA Radiate Security Solution Suite 1.5 RNG Sample
ISARA Corporation <info@isara.com>
v1.5 2018-09: Copyright (C) 2016-2018 ISARA Corporation, All Rights Reserved.

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

HMAC-DRBG is built around the use of a BLAKE2b-256, BLAKE2b-512, SHA2-256,
SHA2-384, SHA2-512, SHA3-256, or SHA3-512 hash function using the HMAC
construction. The toolkit's HMAC-DRBG RNG implementation can be initiated using
any of these hash functions.

## Getting Started

We have created a sample application that demonstrates how to use the
toolkit's HMAC-DRBG RNG implementation.

If the seed and reseed input parameters aren't provided, the sample will use
NIST test vectors to seed and reseed the RNG. To follow the NIST test
specifications, reseeding happens immediately after seeding and the random
data is read in two chunks and both are written to the output file.  If the
NIST vectors are used, the second chunk is compared against the NIST expected
data vector.

If the NIST vectors aren't used, the program follows the same flow and the
user-provided data is used to seed and reseed the RNG. Normally the RNG would
not be immediately reseeded but would be reseeded periodically with new entropy.

Build the sample application:

```
$ cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkitroot/ .
$ make
```

Execute `rng` with default values for the parameters.

Execution and expected outputs:

```
$ ./rng
Running ./rng with the following parameters...
    hash algorithm: IQR_HASHALGO_SHA2_256
    seed: NIST HMAC-DRBG test vectors
    reseed: NIST HMAC-DRBG test vectors
    randomness output file: random.dat
    randomness output byte count: 256

RNG object has been created.
RNG object has been seeded.
RNG object has been reseeded.
RNG data has been read.
Successfully saved random.dat (256 bytes)
Random data has been saved to disk.
Successfully loaded random.dat (256 bytes)
You're using the default NIST data and the output matches!
```

Execute `rng` with seed and reseed data specified by the user.

Execution and expected outputs:

```
$ ./rng --seed seed.dat --reseed reseed.dat
Running ./rng with the following parameters...
    hash algorithm: IQR_HASHALGO_SHA2_256
    seed source: seed.dat
    reseed source: reseed.dat
    randomness output file: random.dat
    randomness output byte count: 256

Successfully loaded seed.dat (48 bytes)
Successfully loaded reseed.dat (32 bytes)
RNG object has been created.
RNG object has been seeded.
RNG object has been reseeded.
RNG data has been read.
Successfully saved random.dat (256 bytes)
Random data has been saved to disk.
```

## rng Usage Details

Command line format:

```
rng
  [--hash blake2b-256|blake2b-512|sha2-256|sha2-384|sha2-512|sha3-256|sha3-512|
  shake128|shake256]
  [--seed <filename>] [--reseed <filename>] [--output <filename>]
  [--count <bytes>]
```

Command line defaults:

```
--hash sha2-256
--output random.dat
--count 256
```

Command line parameter descriptions:

```
[--hash blake2b-256|blake2b-512|sha2-256|sha2-384|sha2-512|sha3-256|sha3-512|
  shake128|shake256]
The hash algorithm to use in the HMAC-DRBG. Uses SHAKE instead of HMAC-DRBG if
shake128 or shake256 is specified.

[--seed <filename>]
Data with which the RNG will be seeded. The entire contents of the file
will be read.

[--reseed <filename>]
Data with which the RNG will be reseeded. The entire contents of the file
will be read.

[--output <filename>]
<filename> is the name of the file where the random numbers are to be saved.

[--count <bytes>]
The number of bytes to read from the random number generator.
```

## Further Reading

* See `iqr_rng.h` in the toolkit's `include` directory.
* http://dx.doi.org/10.6028/NIST.SP.800-90Ar1[NIST Special Publication 800-90A
  Revision 1]
* http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf[SHA-3 Standard:
  Permutation-Based Hash and Extendable-Output Functions]

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
