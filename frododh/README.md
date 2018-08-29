# ISARA Radiate Security Solution Suite 1.5 Frodo Sample
ISARA Corporation <info@isara.com>
v1.5 2018-09: Copyright (C) 2017-2018 ISARA Corporation, All Rights Reserved.

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

### How FrodoDH Differs from the General Case

1.  Alice chooses a public parameter (seed).
2.  Alice chooses a secret value.
3.  Alice uses her secret and the public parameter to calculate a public value.
4.  Alice sends the public value to Bob.
5.  Bob chooses a secret value.
6.  Bob uses his secret, the public parameters, and Alice's public value to
    calculate a public value.
7.  Bob sends the public value to Alice.
8.  Alice uses her secret value and Bob's public value to calculate the shared
    secret.
9.  Bob uses his secret value and Alice's public value to calculate the shared
    secret.

Unlike the general case Bob cannot calculate his public value without first
receiving Alice's public value. In this scenario Alice is the initiator and Bob
is the responder. Initiator and responder are the names used in the code to
differentiate the two sides.

All FrodoDH shared secrets are ephemeral. Unlike the general Diffie-Hellman it
is not possible to reuse the public information to regenerate the secret key.
Doing so weakens the security of the establishment.

## Getting Started

We have created a small sample application that demonstrates how to use the
toolkit's FrodoDH implementation. The application is structured in a way that
isolates the roles played by Alice and Bob by simulating a communication
channel.

To view the code necessary for Alice view `alice.c`, for Bob it is `bob.c`.
These filenames were chosen since Alice and Bob are common cryptographic terms
and a simple client/server model doesn't work for all cases here. Also having a
file called `bob.c` is awesome!

Build the sample application:

```
$ cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkitroot/ .
$ make
```

Execute `frododh` using default parameters.

Execution and expected outputs:

```
$ ./frododh
Running ./frododh with the following parameters...
    Dump data to files: False
    Variant: Recommended


Alice and Bob's secrets match.
```

## frododh Usage Details

Generates a shared secret for Alice and Bob.

Command line format:

```
frododh [--dump] [--variant recommended|paranoid]
```

Command line defaults:

```
--variant recommended
```

Command line parameter descriptions:

```
[--dump]
A switch telling frododh to dump the public information and secrets to file. The
filenames are:
    alice_key.dat - Alice's public information.
    bob_key.dat - Bob's public information.
    alice_secret.dat - Secret derived by Alice.
    bob_secret.dat - Secret derived by Bob.

[--variant recommended|paranoid]
The variant of FrodoDH to use.
```

## Further Reading

* See `iqr_frododh.h` in the toolkit's `include` directory.
* [Alice primer](http://www.gutenberg.org/ebooks/11.txt.utf-8)

## License

See the `LICENSE` file for details:

> Copyright 2017-2018 ISARA Corporation
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
