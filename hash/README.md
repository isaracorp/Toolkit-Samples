# ISARA Radiate(TM) Crypto Suite 2.0 Hash Sample

## Introduction to Hashing Algorithms

Hashing algorithms are one-way functions that take data as input and return
a small fixed-sized buffer of data.  The one-way property means that given the
input and output of the hashing algorithm it would be difficult to create a
different input that would get the hashing algorithm to produce the exact same
output.

SHA2-256, SHA2-384, SHA2-512, SHA3-256 and SHA3-512 are commonly used hashing
functions.

## Getting Started

We have created a small sample application that demonstrates how to use the
toolkit's hash implementation:

Here is the simplest way to use the sample:

Create a digital message and save it to a file called `message.dat`. For
example, on a lark, we used Project Gutenberg's Alice's Adventures in
Wonderland by Lewis Carroll. (It can be freely obtained from
[Project Gutenberg](http://www.gutenberg.org/ebooks/11.txt.utf-8).)
We downloaded the plaintext version and saved it as `message.dat` in the same
directory that contained the compiled executable of the sample.

Build the sample application in a `build` directory:

```
$ mkdir build
$ cd build
$ cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkitroot/ ..
$ make
```

Execute `hash` using default parameters.

Execute the sample with no arguments to use the default parameters, or use
`--help` to list the available options.

## Further Reading

* See `iqr_hash.h` in the toolkit's `include` directory.
* [FIPS 180 - SHA2](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
* [FIPS 202 - SHA3](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)

## License

See the `LICENSE` file for details:

> Copyright (C) 2016-2019, ISARA Corporation
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
