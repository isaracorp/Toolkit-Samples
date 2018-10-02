# ISARA Radiate Security Solution Suite 1.5 Version Sample
ISARA Corporation <info@isara.com>
v1.5 2018-09: Copyright (C) 2016-2018 ISARA Corporation, All Rights Reserved.

## Getting Started

We have created a sample application that demonstrates how to use the
toolkit's version information.

Build the sample application:

```
$ cmake -DIQR_TOOLKIT_ROOT=/path/to/toolkitroot/ .
$ make
```

Execute `version`. It has no parameters.

Execution and expected outputs:

```
$ ./version
Header version: 1.5
                ISARA Radiate Security Solution Suite 1.5
Header version matches library version.
Library build target: Linux/x86_64/GNU
Library build hash:
    3c5d30fd1d5fd322a1568628d13b64953b415894/2018-09-21T14:40:34
```

## version Usage Details

Command line format:

```
version
```

This sample has no command line arguments.

## Further Reading

* See `iqr_version.h` in the toolkit's `include` directory.

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
