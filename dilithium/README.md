# ISARA Radiate™ Quantum-Safe Library 3.0 Dilithium Samples

## Introduction to Signature Schemes

In general, all signature schemes follow a similar pattern. There is one
signer and any number of verifiers.

1.  The signer generates a public and private key pair.
2.  The signer publishes the public key but keeps the private key secret.
3.  The signer uses the private key to sign the digest of a message.
4.  The signer publishes the message and signature.
5.  A verifier obtains the public key, the message and the signature.
6.  A verifier reproduces the digest of the message and verifies it
    against the signature.

With the Dilithium signature scheme, keys only need to be generated once, then
an unlimited number of messages can be signed, and each message and signature
can be verified an unlimited number of times.

## Sample Applications

We have created 3 small sample applications that demonstrate how to use the
toolkit's Dilithium implementation:

* `dilithium_generate_keys` takes care of step 1.
* `dilithium_sign` takes care of step 3.
* `dilithium_verify` takes care of step 6.

The rest of the steps are left up to the underlying system.

As per
[CRYSTALS - Dilithium](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/Round-3-Submissions),
the toolkit's Dilithium implementation provides 123 bits, 182 bits, and 252
bits of classical security with the `IQR_DILITHIUM_2`, `IQR_DILITHIUM_3`,
and `IQR_DILITHIUM_5` variants.

Here is the simplest way to use the samples:

Create a digital message and save it to a file called `message.dat`. For
example, on a lark, we used Project Gutenberg's Alice's Adventures in
Wonderland by Lewis Carroll. (It can be freely obtained from
[Project Gutenberg](http://www.gutenberg.org/ebooks/11.txt.utf-8).)
We downloaded the plaintext version and saved it as `message.dat` in the same
directory that contained the compiled executables of the samples.

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

* See `iqr_dilithium.h` in the toolkit's `include` directory.

## License

See the `LICENSE` file for details:

> Copyright © 2017-2021, ISARA Corporation
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
