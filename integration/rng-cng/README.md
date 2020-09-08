include::../../version.txt[]
# ISARA UNKNOWN ATTRIBUTE UNKNOWN ATTRIBUTE RNG CNG Sample

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

Rather than using HMAC-DRBG from the toolkit, this sample uses the Windows
CNG `BCRYPT_RNG_ALGORITHM` as a source of random data.

## Getting Started

We have created a sample application that demonstrates how to use the
toolkit with your own RNG implementation (in this case, one that relies on
the Windows CNG `BCRYPT_RNG_ALGORITHM` for data).

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
* http://dx.doi.org/10.6028/NIST.SP.800-90Ar1[NIST Special Publication 800-90A
  Revision 1]
* [CNG](https://msdn.microsoft.com/en-us/library/windows/desktop/aa376210%28v=vs.85%29.aspx)
  documentation.

## License

See the `LICENSE` file for details:

> Copyright © 2016-2020, ISARA Corporation
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
