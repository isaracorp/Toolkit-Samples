# ISARA Radiate™ Quantum-Safe Library 2.1 RFC 2898 PBKDF2 Sample

## Introduction to Key Derivation Functions

A key derivation function (or KDF) derives one or more secret keys from a
secret value such as a master key, a password, or a passphrase using a
pseudo-random function.

PBKDF2 (Password-Based Key Derivation Function 2) is specified by the
Internet Engineering Taskforce's
[RFC 2898](https://www.ietf.org/rfc/rfc2898.txt), section A.2.

PBKDF2 uses a pseudorandom function to derive keys. It applies a number
of iterations to the function to increase the cost of deriving a single key,
thereby significantly increasing the cost of a of dictionary attack. The
initial recommended number of iterations was 1000, but this was intended to be
increased over time as CPU speeds increase. Now 1000 iterations would provide
insufficient protection and more iterations should be used. The answer to
"How much more?" is, "We don't know," but
[here's a good read on the subject](http://security.stackexchange.com/a/3993).

Using a salt in the key derivation reduces the ability to use precomputed
hashes for attacks. The standard recommends a salt length of at least 64 bits.

## Getting Started

We have created a sample application that demonstrates how to use the
toolkit's PBKDF2 implementation.

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

Execute the sample with no arguments to use the default parameters, or use
`--help` to list the available options.

## Further Reading

* See `iqr_kdf.h` in the toolkit's `include` directory.
* [RFC 2898](https://www.ietf.org/rfc/rfc2898.txt)
* [Choosing the number of iterations](http://security.stackexchange.com/a/3993)
* [Obligatory XKCD reference](https://xkcd.com/936/)

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
