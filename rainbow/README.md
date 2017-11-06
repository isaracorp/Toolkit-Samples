# ISARA Radiate Security Solution Suite 1.3 Rainbow Samples
ISARA Corporation <info@isara.com>
v1.3 2017-11: Copyright (C) 2017 ISARA Corporation, All Rights Reserved.

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

With the Rainbow signature scheme, keys only need to be generated once, then an
unlimited number of messages can be signed, and each message and signature can
be verified an unlimited number of times.

## Sample Applications

We have created 3 small sample applications that demonstrate how to use the
toolkit's Rainbow implementation:

* `rainbow_generate_keys` takes care of step 1.
* `rainbow_sign` takes care of step 3.
* `rainbow_verify` takes care of step 6.

The rest of the steps are left up to the underlying system.

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

Execute `rainbow_generate_keys` using default parameters.

Execution and expected outputs:

```
$ ./rainbow_generate_keys
Running ./rainbow_generate_keys with the following parameters...
    public key file: pub.key
    private key file: priv.key

Keys have been generated.
Public Key has been exported.
Private Key has been exported.
Successfully saved pub.key (47520 bytes)
Successfully saved priv.key (35097 bytes)
Public and private keys have been saved to disk.
```

Execute `rainbow_sign` using default parameters.

Execution and expected output:

```
$ ./rainbow_sign
Running ./rainbow_sign with the following parameters...
    signature file: sig.dat
    private key file: priv.key
    message data file: message.dat

Successfully loaded message.dat (173595 bytes)
Successfully loaded priv.key (35097 bytes)
Private key has been imported.
Signature has been created.
Successfully saved sig.dat (53 bytes)
Signature has been saved to disk.
```

Execute `rainbow_verify` using default parameters.

Execution and expected output:

```
$ ./rainbow_verify
Running ./rainbow_verify with the following parameters...
    signature file: sig.dat
    public key file: pub.key
    message data file: message.dat

Successfully loaded message.dat (173595 bytes)
Successfully loaded pub.key (47520 bytes)
Successfully loaded sig.dat (53 bytes)
Public key has been loaded successfully!
Rainbow verified the signature successfully!
```

## Sample Applications Usage Details

### rainbow_generate_key

Generates a new private key and public key and saves them to two separate
files.

Command line format:

```
rainbow_generate_keys [--pub <filename>] [--priv <filename>]
```

Command line defaults:

```
--pub pub.key
--priv priv.key
```

Command line parameter descriptions:

```
[--pub <filename>]
<filename> is the name of the file where the public key is to be saved.

[--priv <filename>]
<filename> is the name of the file where the private key is to be saved.
```

### rainbow_sign

Creates the digest of a message, signs the digest and saves the signature to a
file.

Command line format:

```
rainbow_sign [--sig filename] [--priv <filename>]
  [--message <filename>]
```

Command line defaults:

```
--sig sig.dat
--priv priv.key
--message message.dat
```

Command line parameter descriptions:

```
[--sig <filename>]
<filename> is the name of the file where the signature is to be saved.

[--priv <filename>]
<filename> is the name of the file where the private key is stored.

[--message <filename>]
<filename> is the name of the file where the message is stored.
```

### rainbow_verify

Creates the digest of a message and verifies the signature against the digest.

Command line format:

```
rainbow_verify [--sig <filename>] [--pub <filename>]
  [--message <filename>]
```

Command line defaults:

```
--sig sig.dat
--pub pub.key
--message message.dat
```

Command line parameter descriptions:

```
[--sig <filename>]
<filename> is the name of the file where the signature is stored.

[--pub <filename>]
<filename> is the name of the file where the public key is stored.

[--message <filename>]
<filename> is the name of the file where the message is stored.
```

## Further Reading

* See `iqr_rainbow.h` in the toolkit's `include` directory.

## License

See the `LICENSE` file for details:

> Copyright 2017 ISARA Corporation
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
