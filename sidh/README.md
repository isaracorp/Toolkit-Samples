# ISARA Radiate(TM) Crypto Suite 2.0 SIDH Sample

## Introduction to Key Establishment Schemes

In general, all Diffie-Hellman key establishment schemes follow the same
procedure.

1.  Alice and Bob agree on a set of public parameters.
2.  Alice chooses a secret value.
3.  Alice uses her secret and the public parameters to calculate a public value.
4.  Alice sends the public value to Bob.
5.  Bob chooses a secret value.
6.  Bob uses his secret and the public parameters to calculate a public value.
7.  Bob sends the public value to Alice.
8.  Alice uses her secret value and Bob's public value to calculate the shared
    secret.
9.  Bob uses his secret value and Alice's public value to calculate the shared
    secret.

Steps 2-4 for Alice and 5-7 for Bob can be done simultaneously since the
calculations are done independent of the other.

### How SIDH Differs from the General Case

Unlike the general case, Alice and Bob do not perform the same operations during
the execution of SIDH. It is important that the two parties in this key
establishment scheme use the opposite set of operations as each other to ensure
correctness. Alice and Bob are the names used in the code to differentiate the
two sides.

All SIDH shared secrets are ephemeral. Unlike general Diffie-Hellman it is not
possible to reuse the public information to regenerate the secret key. Doing so
weakens the security of the establishment.

## Getting Started

We have created a small sample application that demonstrates how to use the
toolkit's SIDH implementation. The application is structured in a way that
isolates the roles played by Alice and Bob by simulating a communication
channel.

To view the code necessary for Alice view `alice.c`, for Bob it is `bob.c`.

Build the sample application in a `build` directory:

```
$ mkdir build
$ cd build
$ cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkitroot/ ..
$ make
```

Execute the samples with no arguments to use the default parameters, or use
`--help` to list the available options.

## Further Reading

* See `iqr_sidh.h` in the toolkit's `include` directory.
* [Alice primer](http://www.gutenberg.org/ebooks/11.txt.utf-8)

## License

See the `LICENSE` file for details:

> Copyright (C) 2017-2019, ISARA Corporation
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

ISARA Radiate(TM) is a trademark of ISARA Corporation.
