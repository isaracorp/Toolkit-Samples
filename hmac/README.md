# ISARA Radiate Security Solution Suite 1.2 HMAC Sample
ISARA Corporation <info@isara.com>
v1.2 2017-02: Copyright (C) 2016-2017 ISARA Corporation, All Rights Reserved.

## Introduction to Message Authentication Codes

A message authentication code (MAC) is a short piece of information used to
authenticate a message. A MAC algorithm takes a secret key and a message and
produces a tag. The MAC tag protects both a message's data integrity as
well as its authenticity, by allowing verifiers (who also possess the secret
key) to detect any changes to the message content.

HMAC is a MAC which uses a hash function (SHA2-256, SHA2-512, SHA3-256 or
SHA3-512 in our case) to produce the tag.

HMAC is specified by the Internet Engineering Taskforce's
[RFC 2104](https://tools.ietf.org/html/rfc2104).

## Getting Started

We have created a sample application that demonstrates how to use the
toolkit's HMAC implementation.

Here is the simplest way to use the sample:

Create a digital message and save it to a file called `message.dat`. For
example, on a lark, we used Project Gutenberg's Alice's Adventures in
Wonderland by Lewis Carroll. (It can be freely obtained from
[Project Gutenberg](http://www.gutenberg.org/ebooks/11.txt.utf-8).)
We downloaded the plaintext version and saved it as `message.dat` in the same
directory that contained the compiled executable of the sample.

Build the sample application:

```
$ cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkitroot/ .
$ make
```

Execute `hmac` with a single input file to MAC, using default parameters.

Execution and expected outputs:

```
$ ./hmac message.dat
Running ./hmac with the following parameters...
    hash algorithm: IQR_HASHALGO_SHA2_256
    key: ISARA-HMAC-KEY
    data file(s):
      message.dat
    output tag file: tag.dat

HMAC object has been created.
Successfully loaded message.dat (167518 bytes)
HMAC has been created from message.dat
Tag has been calculated.
Successfully saved tag.dat (32 bytes)
Tag has been saved to disk.
```

Execute `hmac` with multiple input files to MAC, using default parameters.
`message.dat` is the same file as in the previous example, `message2.dat`
and `message3.dat` are just files containing arbitrary data. HMAC can operate
on chunks, in this sample we use individual files to represent the chunks.

Execution and expected outputs:

```
$ ./hmac message1.dat message2.dat message3.dat
Running ./hmac with the following parameters...
    hash algorithm: IQR_HASHALGO_SHA2_256
    key: ISARA-HMAC-KEY
    data file(s):
      message.dat
      message2.dat
      message3.dat
    output tag file: tag.dat

HMAC object has been created.
Successfully loaded message.dat (167518 bytes)
HMAC has been updated from message.dat
Successfully loaded message2.dat (50 bytes)
HMAC has been updated from message2.dat
Successfully loaded message3.dat (100 bytes)
HMAC has been updated from message3.dat
Tag has been calculated.
Successfully saved tag.dat (32 bytes)
Tag has been saved to disk.
```

## hmac Usage Details

Command line format:

```
hmac [--hash sha2-256|sha2-512|sha3-256|sha3-512]
    [--key { string <key> | file <filename> }]
    [--tag <filename>] msg1 [msg2 ...]
```

Command line defaults:

```
--hash sha2-256
--key string ISARA-HMAC-KEY
--tag tag.dat
```

Command line parameter descriptions:

```
[--hash sha2-256|sha2-512|sha3-256|sha3-512]
The hash algorithm to use.

[--key string <key>]
Read the key from the command line.

[--key file <filename>]
Read the key from file <filename>. The entire contents of the file
will be read.

[--tag <filename>]
<filename> is the name of the file where the computed tag will be saved.

msg1 [msg2 ...]
One of more files must be provided which contain the parts of the message on
which to calculate the MAC.
```

## Further Reading

* See `iqr_hmac.h` in the toolkit's `include` directory.
* [RFC 2104](https://tools.ietf.org/html/rfc2104)

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
