# ISARA Radiate™ Quantum-Safe Library 3.1 ChaCha20 Sample

## Introduction to Symmetric-Key Cryptography

In symmetric key cryptography, the communicating parties share a single secret
key which is used to encrypt plaintext and decrypt ciphertext.

ChaCha20 is a symmetric-key cryptography algorithm which operates on a shared
256 bit secret key, a 96 bit nonce which must not be reused to encrypt multiple
messages, an initial block counter value and a piece of data to be encrypted or
decrypted.

ChaCha20 is specified by the Internet Engineering Taskforce's
[RFC 8439](https://tools.ietf.org/html/rfc8439).

### Getting Started

We have created 2 small sample applications that demonstrate how to use the
toolkit's ChaCha20 implementation.

* `chacha20_encrypt` takes care of encryption.
* `chacha20_decrypt` takes care of decryption.

Here is the simplest way to use the samples:

Create a digital message and save it to a file called `message.dat`. For
example, on a lark, we used Project Gutenberg's Alice's Adventures in
Wonderland by Lewis Carroll. (It can be freely obtained
[here](http://www.gutenberg.org/ebooks/11.txt.utf-8)).
We downloaded the plaintext version and saved it as `message.dat` in the same
directory that contained the compiled executable of the sample.

Create a binary file named `key.dat` containing your 32 byte key.

We can use `/dev/urandom` on Linux or OSX:

```
$ dd if=/dev/urandom of=key.dat bs=32 count=1
```

Or we can use the `rng` sample provided with the toolkit, although without
a seed to provide proper initial entropy this command will always output the
same "random" bytes:

```
$ ../rng/rng --count 32 --output key.dat
```

Create a binary file named `nonce.dat` containing your 12 byte nonce. Depending
on your particular usage you might use a randomly or pseudo-randomly generated
number, or an initial nonce which is incremented each time you need a new one.

For our sample purposes we just created a nonce with a predefined value:

```
$ echo -n "0123456789ab" > nonce.dat
```

We could also use the toolkit sample's `rng`, with the same seed caveat as
above:

```
$ ../rng/rng --count 12 --output nonce.dat
```

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

* See `iqr_chacha20.h` in the toolkit's `include` directory.
* [RFC 8439](https://tools.ietf.org/html/rfc8439)

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
