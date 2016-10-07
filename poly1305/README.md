# ISARA Toolkit 1.0 Poly1305 MAC Sample
ISARA Corporation <info@isara.com>
v1.0, September 2016: Copyright (C) 2016 ISARA Corporation, All Rights Reserved.

## Introduction to Message Authentication Codes

A message authentication code (MAC) is a short piece of information used to
authenticate a message. A MAC algorithm takes a secret key and a message and
produces a digest. The MAC digest protects both a message's data integrity as
well as its authenticity, by allowing verifiers (who also possess the secret
key) to detect any changes to the message content.

Poly1305 is a MAC algorithm specified by the Internet Engineering Taskforce's
[RFC 7539](https://tools.ietf.org/html/rfc7539).

## Getting Started

We have created a sample application that demonstrates how to use the IQR
Toolkit's Poly1305 implementation.

Here is the simplest way to use the samples:

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

Execute `poly1305` with a single input file to MAC, using default parameters.

Execution and expected outputs:

```
$ ./poly1305 message.dat
Running ./poly1305 with the following parameters...
    key: ****** ISARA-POLY1305-KEY *******
    data file(s):
      message.dat
    tag file: tag.dat

Poly1305 object has been created.
Successfully loaded message.dat (167518 bytes)
Poly1305 tag has been created from message.dat
Poly1305 tag created.
Successfully saved tag.dat (16 bytes)
Poly1305 tag has been saved to disk.
```

Execute `poly1305` with multiple input files to MAC, using default parameters.
`message.dat` is the same file as in the previous example, `message2.dat`
and `message3.dat` are just files containing arbitrary data. Poly1305 can
operate on chunks, in this sample we use individual files to represent the
chunks.

Execution and expected outputs:

```
$ ./poly1305 message.dat message2.dat message3.dat
Running ./poly1305 with the following parameters...
    key: ****** ISARA-POLY1305-KEY *******
    data file(s):
      message.dat
      message2.dat
      message3.dat
    tag file: tag.dat

Poly1305 object has been created.
Successfully loaded message.dat (167518 bytes)
Poly1305 tag has been updated from message.dat
Successfully loaded message2.dat (50 bytes)
Poly1305 tag has been updated from message2.dat
Successfully loaded message3.dat (100 bytes)
Poly1305 tag has been updated from message3.dat
Poly1305 tag created.
Successfully saved tag.dat (16 bytes)
Poly1305 tag has been saved to disk.
```

## poly1305 Usage Details

Command line format:

```
poly1305 [--key { string <key> | file <filename> | none }]
  [--tag <filename>]  msg1 [msg2 ...]
```

Command line defaults:

```
--key string "****** ISARA-POLY1305-KEY *******"
--tag tag.dat
```

Command line parameter descriptions:

```
[--key string <key>]
Read the key from the command line.

[--key file <filename>]
Read the key from file <filename>. The entire contents of the file
will be read.

[--key none]
Don't use a key. This is not recommended, without a key this is basically
just a hashing function.

[--tag <filename>]
Where the resulting tag will be saved.

msg1 [msg2 ...]
One of more files must be provided which contain the parts of the message on
which to calculate the MAC.
```

## Further Reading

* See `iqr_poly1305.h` in the IQR Toolkit's `include` directory.
* [RFC 7539](https://tools.ietf.org/html/rfc7539)

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
