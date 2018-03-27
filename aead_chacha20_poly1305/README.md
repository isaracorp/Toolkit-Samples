# ISARA Radiate Security Solution Suite 1.4 ChaCha20/Poly1305 Sample
ISARA Corporation <info@isara.com>
v1.4 2018-03: Copyright (C) 2016-2018 ISARA Corporation, All Rights Reserved.

## Introduction to Message Authentication Codes

A message authentication code (MAC) is a short piece of information used to
authenticate a message. A MAC algorithm takes a secret key and a message and
produces a digest. The MAC digest protects both a message's data integrity as
well as its authenticity, by allowing verifiers (who also possess the secret
key) to detect any changes to the message content.

Poly1305 is a MAC which is often used in conjunction with ChaCha20 in the
ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data) for
combined encryption and authentication.

Poly1305 is specified by the Internet Engineering Taskforce's
[RFC 7539](https://tools.ietf.org/html/rfc7539).

### Getting Started

We have created 2 small sample applications that demonstrate how to use the
toolkit's Poly1305 implementation. The samples do ChaCha20-Poly1305 AEAD
encryption/decryption and authentication.

* `aead_chacha20_poly1305_encrypt` takes care of encryption and creating the
authentication tag.
* `aead_chacha20_poly1305_decrypt` takes care of decryption and verifying the
authentication tag.

Here is the simplest way to use the samples:

Create a digital message and save it to a file called `message.dat`.

Create some arbitrary-length additional authenticated data and save it to a
file called `aad.dat`. The same additional authenticated data must be used for
encryption and decryption.

Create a binary file named `key.dat` containing your 32 byte key. The same key
must be used for encryption and decryption.

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
The same nonce must be used for encryption and decryption.

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

Execute `aead_chacha20_poly1305_encrypt` with default parameters.

Execution and expected outputs:

```
$ ./aead_chacha20_poly1305_encrypt
Running ./aead_chacha20_poly1305_encrypt with the following parameters...
    key file: key.dat
    nonce file: nonce.dat
    plaintext file: message.dat
    additional authenticated data file: aad.dat
    ciphertext file: ciphertext.dat
    tag file: tag.dat

Successfully loaded key.dat (32 bytes)
Successfully loaded nonce.dat (12 bytes)
Successfully loaded message.dat (114 bytes)
Successfully loaded aad.dat (12 bytes)
Poly1305 key created.
Poly1305 digest created.
Successfully saved tag.dat (16 bytes)
Successfully saved ciphertext.dat (114 bytes)
Ciphertext and tag have been saved to disk.
```

Execute `aead_chacha20_poly1305_decrypt` with default parameters.

Execution and expected outputs:

```
$ ./aead_chacha20_poly1305_decrypt
Running ./aead_chacha20_poly1305_decrypt with the following parameters...
    key file: key.dat
    nonce file: nonce.dat
    ciphertext file: ciphertext.dat
    additional authenticated data file: aad.dat
    tag file: tag.dat
    plaintext file: message.dat

Successfully loaded key.dat (32 bytes)
Successfully loaded nonce.dat (12 bytes)
Successfully loaded ciphertext.dat (114 bytes)
Successfully loaded aad.dat (12 bytes)
Successfully loaded tag.dat (16 bytes)
Poly1305 key created.
Poly1305 digest created.
Authentication success: provided tag matches calculated tag!
Successfully saved message.dat (114 bytes)
Plaintext has been saved to disk.
```

## Sample Applications Usage Details

### aead_chacha20_poly1305_encrypt

Command line format:

```
aead_chacha20_poly1305_encrypt [--key <filename>] [--nonce <filename>]
  [--plaintext <filename>] [--aad <filename>]
  [--ciphertext <filename>] [--tag <filename>]
```

Command line defaults:

```
--key key.dat
--nonce nonce.dat
--plaintext message.dat
--aad aad.dat
--ciphertext ciphertext.dat
--tag tag.dat
```

Command line parameter descriptions:

```
[--key <filename>]
Read the key from file <filename>. Must contain exactly 32 bytes.

[--nonce <filename>]
Read the nonce from file <filename>. Must contain exactly 12 bytes.

[--plaintext <filename>]
The data which will be encrypted and authenticated.

[--aad <filename>]
Arbitrary-length additional authenticated data to include when calculating the
authentication tag.

[--ciphertext <filename>]
Where the resulting ciphertext will be saved.

[--tag <filename>]
Where the resulting authentication tag will be saved.
```

### aead_chacha20_poly1305_decrypt

Command line format:

```
aead_chacha20_poly1305_decrypt [--key <filename>] [--nonce <filename>]
  [--ciphertext <filename>] [--aad <filename>]
  [--tag <filename>] [--plaintext <filename>]
```

Command line defaults:

```
--key key.dat
--nonce nonce.dat
--ciphertext ciphertext.dat
--aad aad.dat
--tag tag.dat
--plaintext message.dat
```

Command line parameter descriptions:

```
[--key <filename>]
Read the key from file <filename>. Must contain exactly 32 bytes.

[--nonce <filename>]
Read the nonce from file <filename>. Must contain exactly 12 bytes.

[--ciphertext <filename>]
The data which will be decrypted after authentication.

[--aad <filename>]
Arbitrary-length additional authenticated data to include when authenticating.

[--tag <filename>]
Tag generated by ChaCha20-Poly1305-AEAD used to authenticate the ciphertext.

[--plaintext <filename>]
Where the resulting plaintext will be saved after authentication succeeds.
```

## Further Reading

* See `iqr_poly1305.h` in the toolkit's `include` directory.
* [RFC 7539](https://tools.ietf.org/html/rfc7539)

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
