# ISARA Radiate Security Solution Suite 1.5 HSS Samples
ISARA Corporation <info@isara.com>
v1.5 2018-09: Copyright (C) 2016-2018 ISARA Corporation, All Rights Reserved.

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

### How HSS Differs from the General Case

1.  The signer generates a public and private key pair. The private key's
    state is also initialized.
2.  The signer publishes the public key but keeps the private key secret. The
    private key state is considered public information.
3.  The signer then uses the private key and state to sign the message.
4.  The signer safely stores the modified state to non-volatile memory.
4.  The signer publishes the message and signature.
5.  A verifier obtains the public key, the message and the signature.
6.  A verifier reproduces the digest of the message and verifies it
    against the signature.

:star: **IMPORTANT**
In step 4, the private key state must be saved due to its  dynamic nature.  If
the signer does not save it after signing, the signer risks using the one time
signature data multiple times which would destroy the security of the scheme.

For HSS, keys only need to be generated once, however, only a limited number
of messages may be signed depending on the height parameter that is chosen by
the signer during key generation.  This height parameter also affects private
key size and signature size.  Each message and signature can be verified an
unlimited number of times.

For a more in-depth discussion about these issues, see the
specification that is referred to in `iqr_hss.h`.

## Sample Applications

We have created 3 small sample applications that demonstrate how to use the
toolkit's HSS implementation:

* `hss_generate_keys` takes care of step 1.
* `hss_sign` takes care of step 3.
* `hss_verify` takes care of step 6.

`hss_sign` also lets the user know how many more signing operations can be
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

Execute `hss_generate_keys` using default parameters.

Execution and expected outputs:

```
$ ./hss_generate_keys
Running ./hss_generate_keys with the following parameters...
    public key file: pub.key
    private key file: priv.key
    private key state file: priv.state
    winternitz value: IQR_HSS_WINTERNITZ_4
    height: IQR_HSS_HEIGHT_5
    strategy: Full Tree

..
Keys have been generated.
Public Key has been exported.
Private Key has been exported.
Private Key State has been exported.
Successfully saved pub.key (60 bytes)
Successfully saved priv.key (56 bytes)
Successfully saved priv.state (2060 bytes)
Public, private keys, and state have been saved to disk.
```

Execute `hss_sign` using default parameters.

Execution and expected output:

```
$ ./hss_sign
Running ./hss_sign with the following parameters...
    signature file: sig.dat
    private key file: priv.key
    private key state file: priv.state
    winternitz value: IQR_HSS_WINTERNITZ_4
    height: IQR_HSS_HEIGHT_5
    strategy: Full Tree
    message data file: message.dat

Successfully loaded message.dat (60422 bytes)
Successfully loaded priv.key (56 bytes)
Successfully loaded priv.state (2060 bytes)
Private key has been imported.
Private key state has been imported.
Signature has been created.
Successfully saved priv.state (2060 bytes)
Successfully saved sig.dat (2352 bytes)
Signature and updated state have been saved to disk.
Number of signatures for this state: 32.
Remaining signatures: 31
```

Execute `hss_verify` using default parameters.

Execution and expected output:

```
$ ./hss_verify
Running ./hss_verify with the following parameters...
    signature file: sig.dat
    public key file: pub.key
    winternitz value: IQR_HSS_WINTERNITZ_4
    height: IQR_HSS_HEIGHT_5
    message data file: message.dat

Successfully loaded message.dat (60422 bytes)
Successfully loaded pub.key (60 bytes)
Successfully loaded sig.dat (2352 bytes)
Public key has been loaded successfully!
HSS verified the signature successfully!
```

## Sample Applications Usage Details

### hss_generate_key

Generates a new private key and public key and saves them to two separate
files.

Command line format:

```
hss_generate_keys [--pub <filename>] [--priv <filename>] [--winternitz 1|2|4|8]
  [--height 5|10|15|20|25] [--strategy bds|full]
```

Command line defaults:

```
--pub pub.key
--priv priv.key
--state priv.state
--strategy full
--winternitz 4
--height 5
```

Command line parameter descriptions:

```
[--pub <filename>]
<filename> is the name of the file where the public key is to be saved.

[--priv <filename>]
<filename> is the name of the file where the private key is to be saved.

[--state <filename>]
<filename> is the name of the file where the private key's state is stored.

[--winternitz 1|2|4|8]
The Winternitz value.

[--height 5|10|15|20|25]
The height of the Merkle Tree in the HSS algorithm.

[--strategy bds|full]
The tree strategy. See iqr_hss.h for details.
```

### hss_sign

Creates the digest of a message, signs the digest and saves the private key and
signature to separate files.

Command line format:

```
hss_sign [--sig <filename>] [--priv <filename>] [--state <filename>]
  [--winternitz 1|2|4|8] [--height 5|10|15|20|25] [--strategy bds|full]
  [--message <filename>]
```

Command line defaults:

```
--sig sig.dat
--priv priv.key
--state priv.state
--strategy full
--winternitz 4
--height 5
--message message.dat
```

Command line parameter descriptions:

```
[--sig <filename>]
<filename> is the name of the file where the signature is to be saved.

[--priv <filename>]
<filename> is the name of the file where the private key is stored.

[--state <filename>]
<filename> is the name of the file where the private key's state is stored.

[--strategy bds|full]
The tree strategy. See iqr_hss.h for details.

[--winternitz 1|2|4|8]
This must be the same value as was passed into hss_generate_keys.

[--height 5|10|15|20|25]
This must be the same value as was passed into hss_generate_keys.

[--message <filename>]
<filename> is the name of the file where the message is stored.
```

### hss_verify

Creates the digest of a message and verifies the signature against the digest.

Command line format:

```
hss_verify [--sig <filename>] [--pub <filename>] [--winternitz 1|2|4|8]
  [--height 5|10|15|20|25] [--message <filename>]
```

Command line defaults:

```
--sig sig.dat
--pub pub.key
--winternitz 4
--height 5
--message message.dat
```

Command line parameter descriptions:

```
[--sig <filename>]
<filename> is the name of the file where the signature is stored.

[--pub <filename>]
<filename> is the name of the file where the public key is stored.

[--winternitz 1|2|4|8]
This must be the same value as was passed into hss_generate_keys.

[--height 5|10|15|20|25]
This must be the same value as was passed into hss_generate_keys.

[--message <filename>]
<filename> is the name of the file where the message is stored.
```

## Further Reading

* See `iqr_hss.h` in the toolkit's `include` directory.
* [Hash-Based Signatures](https://tools.ietf.org/html/draft-mcgrew-hash-sigs-11)
  IETF Draft

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
