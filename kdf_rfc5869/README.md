# ISARA Radiate™ Quantum-safe Toolkit 2.0 RFC 5869 KDF Sample

## Introduction to Key Derivation Functions

A key derivation function (or KDF) derives one or more secret keys from a
secret value such as a master key, a password, or a passphrase using a
pseudo-random function.

HMAC-based Extract-and-Expand Key Derivation Function is specified by the
Internet Engineering Taskforce's
[RFC 5869](https://tools.ietf.org/html/rfc5869).

This KDF uses a HMAC function to derive keys. It takes as input some initial
keying material (IKM), and optionally a salt value and application-specific
information.

## Getting Started

We have created a sample application that demonstrates how to use the
toolkit's RFC 5869 HKDF implementation.

Normally the IKM would be a blob of binary data and would contain non-printable
characters and so couldn't be read in from the command line. For ease of use
in this sample we allow the IKM to be entered via the command line, but also
have an option to read the IKM from a file in case you want to use some real
world IKM.

Build the sample application in a `build` directory:

```
$ mkdir build
$ cd build
$ cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkitroot/ ..
$ make
```

Execute the sample with no arguments to use the default parameters, or use
`--help` to list the available options.

## Further Reading

* See `iqr_kdf.h` in the toolkit's `include` directory.
* [RFC 5869](https://tools.ietf.org/html/rfc5869)

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
