# ISARA Toolkit 1.1 LMS Samples
ISARA Corporation <info@isara.com>
v1.1, November 2016: Copyright (C) 2016 ISARA Corporation, All Rights Reserved.

## Introduction to Signature Schemes

In general, all signature schemes follow a similar pattern.  There is one
signer and any number of verifiers.

1.  The signer generates a public and private key pair.
2.  The signer publishes the public key but keeps the private key secret.
3.  The signer uses the private key to sign the digest of a message.
4.  The signer publishes the message and signature.
5.  A verifier obtains the public key, the message and the signature.
6.  A verifier reproduces the digest of the message and verifies it
    against the signature.

Generally speaking, keys only need to be generated once, an unlimited number
of messages can be signed, and each message and signature can be verified
an unlimited number of times.

### How LMS Differs from the General Case

1.  The signer generates a public and private key pair.
2.  The signer publishes the public key but keeps the private key secret.
3.  **The signer must save the index q + 1 since q must not be reused.**
    The signer then uses the private key and q to sign the digest of a message.
4.  The signer publishes the message and signature.
5.  A verifier obtains the public key, the message and the signature.
6.  A verifier reproduces the digest of the message and verifies it
    against the signature.

:star: **IMPORTANT**
In step 3, the OTS index value `q + 1` must be saved due to its
dynamic nature.  If the signer does not save it before signing the digest,
the signer risks using the one time signature data multiple times which
would destroy the security of the scheme.

For LMS, keys only need to be generated once, however, only a limited number
of messages may be signed depending on the height parameter that is chosen by
the signer during key generation.  This height parameter also affects private
key size and signature size.  Each message and signature can be verified an
unlimited number of times.

For a more in-depth discussion about these issues, see the
specification that is referred to in `iqr_lms.h`.

## Sample Applications

We have created 3 small sample applications that demonstrate how to use the IQR
Toolkit's LMS implementation:

* `lms_generate_keys` takes care of step 1.
* `lms_sign` takes care of step 3.
* `lms_verify` takes care of step 6.

`lms_sign` also lets the user know how many more signing operations can be
done with the private key.  The rest of the steps are left up to the underlying
system.

Here is the simplest way to use the samples:

Create a digital message and save it to a file called `message.dat`. For
example, on a lark, we used Project Gutenberg's Alice's Adventures in
Wonderland by Lewis Carroll. (It can be freely obtained from
[Project Gutenberg](http://www.gutenberg.org/ebooks/11.txt.utf-8).)
We downloaded the plaintext version and saved it as `message.dat` in the same
directory that contained the compiled executables of the samples.

Build the sample application:

```
$ cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkitroot/ .
$ make
```

Execute `lms_generate_keys` using default parameters.

Execution and expected outputs:

```
$ ./lms_generate_keys
Running ./lms_generate_keys with the following parameters...
    security string: ** ISARA LMS KEY IDENTIFIER ***
    public key file: pub.key
    private key file: priv.key
    winternitz value: IQR_LMS_WINTERNITZ_4
    height: IQR_LMS_HEIGHT_5

Keys have been generated.
Public Key has been exported.
Private Key has been exported.
Successfully saved pub.key (68 bytes)
Successfully saved priv.key (68736 bytes)
Public and private keys have been saved to disk.
```

Execute `lms_sign` using default parameters.

Execution and expected output:

```
$ ./lms_sign --q 6
Running ./lms_sign with the following parameters...
    security string: ** ISARA LMS KEY IDENTIFIER ***
    signature file: sig.dat
    private key file: priv.key
    winternitz value: IQR_LMS_WINTERNITZ_4
    height: IQR_LMS_HEIGHT_5
    q: 6
    message data file: message.dat

Successfully loaded message.dat (167518 bytes)
Number of signatures for this private key: 32.
Successfully loaded priv.key (68736 bytes)
Private key has been imported.
Signature has been created.
The private key can sign 25 more messages.
IMPORTANT: Next time you sign, use q+1 (7).
Successfully saved sig.dat (2348 bytes)
Signature has been saved to disk.
```

Execute `lms_verify` using default parameters.

Execution and expected output:

```
$ ./lms_verify
Running ./lms_verify with the following parameters...
    security string: ** ISARA LMS KEY IDENTIFIER ***
    signature file: sig.dat
    public key file: pub.key
    winternitz value: IQR_LMS_WINTERNITZ_4
    height: IQR_LMS_HEIGHT_5
    message data file: message.dat

Successfully loaded message.dat (167518 bytes)
Successfully loaded pub.key (68 bytes)
Successfully loaded sig.dat (2348 bytes)
Public key has been loaded successfully!
LMS verified the signature successfully!
```

## Sample Applications Usage Details

### lms_generate_key

Generates a new private key and public key and saves them to two separate
files.

Command line format:

```
lms_generate_keys [--security <identifier>] [--pub <filename>]
    [--priv <filename>] [--winternitz 1|2|4|8]
    [--height 5|10|20]
```

Command line defaults:

```
--security "** ISARA LMS KEY IDENTIFIER ***"
--pub pub.key
--priv priv.key
--winternitz 4
--height 5
```

Command line parameter descriptions:

```
[--security <identifier>]
The security identifier for the private key. This value must be distinct from
all other identifiers and should be chosen via a pseudo-random function.
However, for the convenience of the end user, in this sample we use a printable
string and initialize it to a simple default. The security identified must be
31 bytes long.

[--pub <filename>]
<filename> is the name of the file where the public key is to be saved.

[--priv <filename>]
<filename> is the name of the file where the private key is to be saved.

[--hash 16|32]
The size of the hashes to be used by the LMS algorithm.

[--winternitz 1|2|4|8]
The Winternitz value.

[--height 5|10|20]
The height of the Merkle Tree in the LMS algorithm.
```

### lms_sign

Creates the digest of a message, signs the digest and saves the private key and
signature to separate files.

Command line format:

```
lms_sign --q <number> [--security <identifier>]
    [--sig filename] [--priv <filename>]
    [--winternitz 1|2|4|8] [--height 5|10|20]
    [--message <filename>]
```

Command line defaults:

```
--security "** ISARA LMS KEY IDENTIFIER ***"
--sig sig.dat
--priv priv.key
--winternitz 4
--height 5
--message message.dat
```

Command line parameter descriptions:

```
[--q <number>]
This must be provided by the user. DO NOT REUSE q!

[--security <identifier>]
This must be the same value as was passed into lms_generate_keys.

[--sig <filename>]
<filename> is the name of the file where the signature is to be saved.

[--priv <filename>]
<filename> is the name of the file where the private key is stored.

[--winternitz 1|2|4|8]
This must be the same value as was passed into lms_generate_keys.

[--height 5|10|20]
This must be the same value as was passed into lms_generate_keys.

[--message <filename>]
<filename> is the name of the file where the message is stored.
```

### lms_verify

Creates the digest of a message and verifies the signature against the digest.

Command line format:

```
lms_verify [--security <identifier>] [--sig <filename>] [--pub <filename>]
    [--winternitz 1|2|4|8] [--height 5|10|20]
    [--message <filename>]
```

Command line defaults:

```
--security "** ISARA LMS KEY IDENTIFIER ***"
--sig sig.dat
--pub pub.key
--winternitz 4
--height 5
--message message.dat
```

Command line parameter descriptions:

```
[--security <identifier>]
This must be the same value as was passed into lms_generate_keys.

[--sig <filename>]
<filename> is the name of the file where the signature is stored.

[--pub <filename>]
<filename> is the name of the file where the public key is stored.

[--winternitz 1|2|4|8]
This must be the same value as was passed into lms_generate_keys.

[--height 5|10|20]
This must be the same value as was passed into lms_generate_keys.

[--message <filename>]
<filename> is the name of the file where the message is stored.
```

## Further Reading

* See `iqr_lms.h` in the IQR Toolkit's `include` directory.
* [Hash-Based Signatures](https://tools.ietf.org/html/draft-mcgrew-hash-sigs-04)
  IETF Draft

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
