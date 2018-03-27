# ISARA Radiate Security Solution Suite 1.4 XMSS Samples
ISARA Corporation <info@isara.com>
v1.4 2018-03: Copyright (C) 2017-2018 ISARA Corporation, All Rights Reserved.

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

### How XMSS Differs from the General Case

1.  The signer generates a public and private key pair.
2.  The signer publishes the public key but keeps the private key secret.
3.  **The signer must save `index + 1` since an index must not be reused.**
    The signer then uses the private key and index to sign the digest of a
    message.
4.  The signer publishes the message and signature.
5.  A verifier obtains the public key, the message and the signature.
6.  A verifier reproduces the digest of the message and verifies it
    against the signature.

:star: **IMPORTANT**
In step 3, the OTS index value `index + 1` must be saved due to its
dynamic nature.  If the signer does not save it before signing the digest,
the signer risks using the one time signature data multiple times which
would destroy the security of the scheme.

For XMSS, keys only need to be generated once, however, only a limited number
of messages may be signed depending on the height parameter that is chosen by
the signer during key generation.  This height parameter also affects private
key size and signature size.  Each message and signature can be verified an
unlimited number of times.

For a more in-depth discussion about these issues, see the
specification that is referred to in `iqr_xmss.h`.

## Sample Applications

We have created 3 small sample applications that demonstrate how to use the
toolkit's XMSS implementation:

* `xmss_generate_keys` takes care of step 1.
* `xmss_sign` takes care of step 3.
* `xmss_verify` takes care of step 6.

`xmss_sign` also lets the user know how many more signing operations can be
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

Execute `xmss_generate_keys` using default parameters.

Execution and expected outputs:

```
$ ./xmss_generate_keys
Running ./xmss_generate_keys with the following parameters...
    public key file: pub.key
    private key file: priv.key
    height: IQR_XMSS_HEIGHT_10

Keys have been generated.
Public Key has been exported.
Private Key has been exported.
Successfully saved pub.key (68 bytes)
Successfully saved priv.key (65580 bytes)
Public and private keys have been saved to disk.
```

Execute `xmss_sign` using default parameters.

Execution and expected output:

```
$ ./xmss_sign --index 6
Running ./xmss_sign with the following parameters...
    signature file: sig.dat
    private key file: priv.key
    height: IQR_XMSS_HEIGHT_10
    index: 6
    message data file: message.dat

Successfully loaded message.dat (167518 bytes)
Successfully loaded priv.key (65580 bytes)
Private key has been imported.
Number of signatures for this private key: 1024.
Signature has been created.
IMPORTANT: Next time you sign, use index+1 (7).
Successfully saved sig.dat (2500 bytes)
Signature has been saved to disk.
```

Execute `xmss_verify` using default parameters.

Execution and expected output:

```
$ ./xmss_verify
Running ./xmss_verify with the following parameters...
    signature file: sig.dat
    public key file: pub.key
    height: IQR_XMSS_HEIGHT_10
    message data file: message.dat

Successfully loaded message.dat (167518 bytes)
Successfully loaded pub.key (68 bytes)
Successfully loaded sig.dat (2500 bytes)
Public key has been loaded successfully!
XMSS verified the signature successfully!
```

## Sample Applications Usage Details

### xmss_generate_key

Generates a new private key and public key and saves them to two separate
files.

Command line format:

```
xmss_generate_keys [--pub <filename>]
    [--priv <filename>] [--height 10|16|20]
```

Command line defaults:

```
--pub pub.key
--priv priv.key
--height 10
```

Command line parameter descriptions:

```
[--pub <filename>]
<filename> is the name of the file where the public key is to be saved.

[--priv <filename>]
<filename> is the name of the file where the private key is to be saved.

[--height 10|16|20]
The height of the Merkle Tree in the XMSS algorithm.
```

### xmss_sign

Creates the digest of a message, signs the digest and saves the private key and
signature to separate files.

Command line format:

```
xmss_sign --index <number>
    [--sig filename] [--priv <filename>]
    [--height 10|16|20] [--message <filename>]
```

Command line defaults:

```
--sig sig.dat
--priv priv.key
--height 10
--message message.dat
```

Command line parameter descriptions:

```
[--index <number>]
This must be provided by the user. DO NOT REUSE index!

[--sig <filename>]
<filename> is the name of the file where the signature is to be saved.

[--priv <filename>]
<filename> is the name of the file where the private key is stored.

[--height 10|16|20]
This must be the same value as was passed into xmss_generate_keys.

[--message <filename>]
<filename> is the name of the file where the message is stored.
```

### xmss_verify

Creates the digest of a message and verifies the signature against the digest.

Command line format:

```
xmss_verify [--sig <filename>] [--pub <filename>]
    [--height 10|16|20] [--message <filename>]
```

Command line defaults:

```
--sig sig.dat
--pub pub.key
--height 10
--message message.dat
```

Command line parameter descriptions:

```
[--sig <filename>]
<filename> is the name of the file where the signature is stored.

[--pub <filename>]
<filename> is the name of the file where the public key is stored.

[--height 10|16|20]
This must be the same value as was passed into xmss_generate_keys.

[--message <filename>]
<filename> is the name of the file where the message is stored.
```

## Further Reading

* See `iqr_xmss.h` in the toolkit's `include` directory.
* https://datatracker.ietf.org/doc/draft-irtf-cfrg-xmss-hash-based-signatures[XMSS:
  Extended Hash-Based Signatures] IETF Draft

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
