# ISARA Toolkit 1.1 McEliece QC-MDPC Samples
ISARA Corporation <info@isara.com>
v1.1, November 2016: Copyright (C) 2016 ISARA Corporation, All Rights Reserved.

## Introduction to Public Key Cryptography

In general, all public key cryptography schemes follow a similar pattern. There
are any number of senders and a single receiver.

1.  The receiver generates a public and private key pair.
2.  The receiver publishes the public key but keeps the private key secret.
3.  A sender obtains the public key.
4.  That sender encrypts a message with the public key.
5.  That sender sends the encrypted message to the receiver.
6.  The receiver obtains the encrypted message.
7.  The receiver decrypts the encrypted message with the private key.

Generally speaking, keys only need to be generated once, an unlimited number
of messages can be encrypted but only the receiver can decrypt the message.
The McEliece cryptosystem follows this pattern.

## Getting Started

We have created 3 small sample applications that demonstrate how to use the IQR
Toolkit's McEliece QC-MDPC implementation:

* `mceliece_generate_keys` takes care of step 1.
* `mceliece_encrypt` takes care of step 4.
* `mceliece_decrypt` takes care of step 7.

As per [MDPC-McEliece:](https://eprint.iacr.org/2012/409.pdf)New McEliece
Variants from Moderate Density Parity-Check Codes, the following key sizes (in
bits) are supported for the 128 bits and 256 bits security levels:

* 9857 provides 128 bits of security.
* 14866 provides 128 bits of security.
* 20409 provides 128 bits of security.
* 32771 provides 256 bits of security.
* 45062 provides 256 bits of security.
* 61449 provides 256 bits of security.

Note that bigger key sizes will lead to slower key generation, encryption, and
decryption.

Here is the simplest way to use the samples:

Build the sample application:

```
$ cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkitroot/ .
$ make
```

Create a message and save it to a file called message.dat. For example,
on a lark, we used Alice's Adventures in Wonderland by Lewis
Carroll. (It can be freely obtained from
[Project Gutenburg](http://www.gutenberg.org/ebooks/11.txt.utf-8)).
We downloaded the plaintext version and saved it as message.dat in the same
directory that contained the compiled executables of the samples.

Execute `mceliece_generate_keys` using default parameters.

Execution and expected outputs:

```
$ ./mceliece_generate_keys
Running ./mceliece_generate_keys with the following parameters:
    public key file: pub.key
    private key file: priv.key
    security level: 128
    key size: 9857
The global context has been created.
Hash functions have been registered in the global context.
RNG object has been created.
McEliece QC-MDPC parameter structure has been created.
McEliece QC-MDPC public and private key-pair has been created
Public key has been exported.
Private key has been exported.
Successfully saved pub.key (1233 bytes)
Successfully saved priv.key (2465 bytes)
Public and private keys have been saved to disk.
```

Execute `mceliece_encrypt` using default parameters.

Execution and expected output:

```
$ ./mceliece_encrypt
Running ./mceliece_encrypt with the following parameters:
    public key file: pub.key
    plaintext file: message.dat
    ciphertext file: ciphertext.dat
    security level: 128
    key size: 9857
The global context has been created.
Hash functions have been registered in the global context.
RNG object has been created.
McEliece QC-MDPC parameter structure has been created.
Successfully loaded pub.key (1233 bytes)
Successfully loaded message.dat (416863 bytes)
McEliece QC-MDPC encryption completed.
Successfully saved ciphertext.dat (419328 bytes)
```

Execute `mceliece_decrypt` using default parameters.

Execution and expected output:

```
$ ./mceliece_decrypt
Running ./mceliece_decrypt with the following parameters:
    private key file: priv.key
    ciphertext file: ciphertext.dat
    plaintext file: decrypted_message.dat
    security level: 128
    key size: 9857
The global context has been created.
Hash functions have been registered in the global context.
McEliece QC-MDPC parameter structure has been created.
Successfully loaded priv.key (2465 bytes)
Successfully loaded ciphertext.dat (419328 bytes)
McEliece QC-MDPC decryption completed.
Successfully saved decrypted_message.dat (416863 bytes)
```

## Sample Applications Usage Details

Note that the user is able to specify a `--security` parameter or a `--keysize`
parameter.  Once it is specified for `mceliece_generate_key`, it must be used
the same way with the same value for `mceliece_encrypt` and `mceliece_decrypt`
or else the samples will not properly encrypt and decrypt.

### mceliece_generate_key

Generates a new public key and private key and saves them to two separate
files.

Command line format:

```
mceliece_generate_keys {[--security <level>] | [--keysize <value>]}
    [--pub <filename>] [--priv <filename>]
```

Command line defaults:

```
--keysize 9857
--pub pub.key
--priv priv.key
```

Command line parameter descriptions:

```
[--security <level>]
Do not specify both security level and key size.
Valid security level are:
    * 128
    * 256

[--keysize <bits>]
Do not specify both security level and key size.
Valid key size values are:
    * 9857
    * 14866
    * 20409
    * 32771
    * 45062
    * 61449

[--pub <filename>]
<filename> is the name of the file where the public key is to be saved.

[--priv <filename>]
<filename> is the name of the file where the private key is to be saved.
```

### mceliece_encrypt

Encrypts a message and saves the ciphertext.

Command line format:

```
mceliece_encrypt {[--security <level>] | [--keysize <value>]}
    [--pub <filename>] [--plaintext <filename>] [--ciphertext <filename>]
```

Command line defaults:

```
--keysize 9857
--pub pub.key
--plaintext message.dat
--ciphertext ciphertext.dat
```

Command line parameter descriptions:

```
[--security <level>]
This must be the same value as was passed into mceliece_generate_keys.

[--keysize <bits>]
This must be the same value as was passed into mceliece_generate_keys.

[--pub <filename>]
<filename> is the name of the file where the public key is stored.

[--plaintext <filename>]
<filename> is the name of the file where the plain text is stored.

[--ciphertext <filename>]
<filename> is the name of the file where the ciphertext is to be saved.
```

### mceliece_decrypt

Decrypts an encrypted message and saves the plaintext.

Command line format:

```
mceliece_decrypt {[--security <level>] | [--keysize <value>]}
    [--priv <filename>] [--ciphertext <filename>] [--plaintext <filename>]
```

Command line defaults:

```
--keysize 9857
--priv priv.key
--ciphertext ciphertext.dat
--plaintext decrypted_message.dat
```

Command line parameter descriptions:

```
[--security <level>]
This must be the same value as was passed into mceliece_generate_keys.

[--keysize <bits>]
This must be the same value as was passed into mceliece_generate_keys.

[--priv <filename>]
<filename> is the name of the file where the private key is stored.

[--ciphertext <filename>]
<filename> is the name of the file where the ciphertext is stored.

[--plaintext <filename>]
<filename> is the name of the file where the plain text is to be saved.
```

## Further Reading

* See `iqr_mceliece.h` in the IQR Toolkit's `include` directory.
* [MDPC-McEliece:](https://eprint.iacr.org/2012/409.pdf)New McEliece Variants
  from Moderate Density Parity-Check Codes

## License

See the `LICENSE` file for details:

> Copyright 2016 ISARA Corporation
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
