# ISARA Radiate Security Solution Suite 1.3 ChaCha20 Sample
ISARA Corporation <info@isara.com>
v1.3 2017-11: Copyright (C) 2016-2017 ISARA Corporation, All Rights Reserved.

## Introduction to Symmetric-Key Cryptography

In symmetric key cryptography, the communicating parties share a single secret
key which is used to encrypt plaintext and decrypt ciphertext.

ChaCha20 is a symmetric-key cryptography algorithm which operates on a shared
256 bit secret key, a 96 bit nonce which must not be reused to encrypt multiple
messages, an initial block counter value and a piece of data to be encrypted or
decrypted.

ChaCha20 is specified by the Internet Engineering Taskforce's
[RFC 7539](https://tools.ietf.org/html/rfc7539).

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

Build the sample application:

```
$ cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkitroot/ .
$ make
```

Execute `chacha20_encrypt` with default parameters.

Execution and expected outputs:

```
$ ./chacha20_encrypt
Running ./chacha20_encrypt with the following parameters...
    key file: key.dat
    nonce file: nonce.dat
    initial counter: 0
    plaintext file: message.dat
    ciphertext file: ciphertext.dat

Successfully loaded key.dat (32 bytes)
Successfully loaded nonce.dat (12 bytes)
Successfully loaded message.dat (167518 bytes)
ChaCha20 encrypt completed.
Successfully saved ciphertext.dat (167518 bytes)
Ciphertext has been saved to disk.
```

Execute `chacha20_decrypt` with default parameters.

Execution and expected outputs:

```
$ ./chacha20_decrypt
Running ./chacha20_decrypt with the following parameters...
    key file: key.dat
    nonce file: nonce.dat
    initial counter: 0
    ciphertext file: ciphertext.dat
    plaintext file: plaintext.dat

Successfully loaded key.dat (32 bytes)
Successfully loaded nonce.dat (12 bytes)
Successfully loaded ciphertext.dat (167518 bytes)
ChaCha20 decrypt completed.
Successfully saved plaintext.dat (167518 bytes)
Plaintext has been saved to disk.
```

## Sample Applications Usage Details

### chacha20_encrypt

Command line format:

```
chacha20_encrypt [--key <filename>] [--nonce <filename>]
  [--initial_counter <counter>] [--plaintext <filename>]
  [--ciphertext <filename>]
```

Command line defaults:

```
--key key.dat
--nonce nonce.dat
--initial_counter 0
--plaintext message.dat
--ciphertext ciphertext.dat
```

Command line parameter descriptions:

```
[--key <filename>]
Read the key from file <filename>. Must contain exactly 32 bytes.

[--nonce <filename>]
Read the nonce from file <filename>. Must contain exactly 12 bytes.

[--initial_counter counter]
The value which the ChaCha20 initial block counter will be initialized to.

[--plaintext <filename>]
The data which will be encrypted.

[--ciphertext <filename>]
Where the resulting ciphertext will be saved.
```

### chacha20_decrypt

Command line format:

```
chacha20_decrypt [--key <filename>] [--nonce <filename>]
  [--initial_counter <counter>] [--ciphertext <filename>]
  [--plaintext <filename>]
```

Command line defaults:

```
--key key.dat
--nonce nonce.dat
--initial_counter 0
--ciphertext ciphertext.dat
--plaintext plaintext.dat
```

Command line parameter descriptions:

```
[--key <filename>]
Read the key from file <filename>. Must contain exactly 32 bytes.

[--nonce <filename>]
Read the nonce from file <filename>. Must contain exactly 12 bytes.

[--initial_counter counter]
The value which the ChaCha20 initial block counter will be initialized to.

[--ciphertext <filename>]
The data which will be decrypted.

[--plaintext <filename>]
Where the resulting plaintext will be saved.
```

## Further Reading

* See `iqr_chacha20.h` in the toolkit's `include` directory.
* [RFC 7539](https://tools.ietf.org/html/rfc7539)

## License

See the `LICENSE` file for details:

> Copyright 2016-2017 ISARA Corporation
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
