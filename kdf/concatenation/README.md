# ISARA Radiate™ Quantum-Safe Library 3.1 Concatenation KDF Sample

## Introduction to Key Derivation Functions

A key derivation function (or KDF) derives one or more secret keys from a
secret value such as a master key, a password, or a passphrase using a
pseudo-random function.

[NIST SP 800-56C](http://dx.doi.org/10.6028/NIST.SP.800-56Cr1)Option 1
Concatenation KDF is specified by NIST.

This KDF uses concatenation and a hash function to derive keys. It takes as
input a shared secret, and optionally application specific information
formatted per the specification.

## Getting Started

We have created a sample application that demonstrates how to use the
toolkit's Concatenation KDF implementation.

Normally the shared secret would be a blob of binary data and would contain
non-printable characters and so couldn't be read in from the command line.
For ease of use in this sample we allow the shared secret to be entered via
the command line, but also have an option to read it from a file in case you
want to use a real world shared secret.

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
* [NIST SP 800-56C](http://dx.doi.org/10.6028/NIST.SP.800-56Cr1)Option 1
  Concatenation KDF specification

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
