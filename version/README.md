# ISARA Radiate™ Quantum-Safe Library 2.0a Version Sample

## Getting Started

We have created a sample application that demonstrates how to use the
toolkit's version information.

**NOTE**
Before building the samples, copy one of the CPU-specific versions of the
toolkit libraries into a `lib` directory. For example, to build the samples
for Intel Core 2 or better CPUs, copy the contents of `lib_core2` into `lib`.

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

Execute `version`. It has no parameters.

## Further Reading

* See `iqr_version.h` in the toolkit's `include` directory.

## License

See the `LICENSE` file for details:

> Copyright © 2016-2019, ISARA Corporation
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
