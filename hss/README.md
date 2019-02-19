# ISARA Radiate(TM) Crypto Suite 2.0 HSS Samples

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

**IMPORTANT**
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

We have created small sample applications that demonstrate how to use the
toolkit's HSS implementation:

* `hss_generate_keys` takes care of step 1.
* `hss_sign` takes care of step 3.
* `hss_verify` takes care of step 6.

`hss_sign` also lets the user know how many more signing operations can be
done with the private key.  The rest of the steps are left up to the underlying
system.

There's also an `hss_detach` sample showing you how to detach parts of a
private key so they can be distributed between processes.

Here is the simplest way to use the samples:

Create a digital message and save it to a file called `message.dat`. For
example, on a lark, we used Project Gutenberg's Alice's Adventures in
Wonderland by Lewis Carroll. (It can be freely obtained from
[Project Gutenberg](http://www.gutenberg.org/ebooks/11.txt.utf-8).)
We downloaded the plaintext version and saved it as `message.dat` in the same
directory that contained the compiled executables of the samples.

Build the sample application in a `build` directory:

```
$ mkdir build
$ cd build
$ cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkitroot/ ..
$ make
```

Execute the samples with no arguments to use the default parameters, or use
`--help` to list the available options.

## Further Reading

* See `iqr_hss.h` in the toolkit's `include` directory.
* [Hash-Based Signatures](https://tools.ietf.org/html/draft-mcgrew-hash-sigs-15)
  IETF Draft

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
