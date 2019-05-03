# Copyright (C) 2016-2019, ISARA Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

string (TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_LOWER)
string (TOLOWER "${CMAKE_SYSTEM_NAME}" CMAKE_SYSTEM_NAME_LOWER)

# Compiler specific flags
if ("${CMAKE_C_COMPILER_ID}" MATCHES "Clang")
    ### Clang
    add_compile_options (-Weverything)
    add_compile_options (-Wno-vla)
    add_compile_options (-Wno-packed)
    add_compile_options (-Wno-padded)
    if (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 3.7)
        # Not sure of the exact version when this was added; clang 3.4 on
        # FreeBSD 10.3 doesn't have it.
        add_compile_options (-Wno-reserved-id-macro)
    endif ()
    add_compile_options (-Wno-disabled-macro-expansion)
    add_compile_options (-Wno-documentation-unknown-command)
    ## Will rely on gcc figuring this error out if it is applicable.
    add_compile_options (-Wno-cast-align)
    ## If clang learns about the C99 spec we can remove this.
    add_compile_options (-Wno-missing-field-initializers)
    add_compile_options (-fvisibility=hidden)
    add_compile_options (-std=c99)
    ## We'll update the samples to use any changed APIs.
    add_compile_options (-Wno-deprecated-declarations)

    ## Release
    if (CMAKE_BUILD_TYPE_LOWER STREQUAL "release")
        add_compile_options (-O3)
        add_compile_options (-DNDEBUG)
        add_compile_options (-D_FORTIFY_SOURCE=2)
        add_compile_options (-Werror)

    ## Debug
    elseif (CMAKE_BUILD_TYPE_LOWER STREQUAL "debug")
        add_compile_options (-UNDEBUG)
        add_compile_options (-O0)

    ## Analysis
    elseif (CMAKE_BUILD_TYPE_LOWER STREQUAL "analysis")
        add_compile_options (-DNDEBUG)
        add_compile_options (-O0)
    endif ()

    if (CMAKE_C_COMPILER_VERSION VERSION_GREATER 5.2)
        # GCC 5.2
        if (NOT BUILD_SERVER)
            add_compile_options (-fdiagnostics-color=always)
        endif ()
    endif ()

    ## Platform specific stuff
    if (("${CMAKE_SYSTEM_NAME_LOWER}" MATCHES "linux|windows|cygwin"))
        # Linux headers don't define strnlen() unless you define
        # _POSIX_C_SOURCE; the samples definitely conform to POSIX 1003.2-2008.
        add_compile_options("-D_POSIX_C_SOURCE=200809L")
    endif ()

    if (NOT ("${CMAKE_SYSTEM_NAME_LOWER}" MATCHES "cygwin"))
        # Cygwin warns you that -fPIC isn't necessary. That doesn't mix well
        # with -Werror unfortunately.
        add_compile_options (-fPIC)
    endif ()

elseif ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
    ## GCC
    add_compile_options (-Wall)
    add_compile_options (-Wextra)
    add_compile_options (-Waggregate-return)
    add_compile_options (-Wbad-function-cast)
    add_compile_options (-Wcast-align)
    add_compile_options (-Wcast-qual)
    add_compile_options (-Wfloat-equal)
    add_compile_options (-Wformat-security)
    add_compile_options (-Wformat=2)
    add_compile_options (-Winit-self)
    add_compile_options (-Wmissing-include-dirs)
    add_compile_options (-Wmissing-noreturn)
    add_compile_options (-Wmissing-prototypes)
    add_compile_options (-Wnested-externs)
    add_compile_options (-Wold-style-definition)
    add_compile_options (-Wpedantic)
    add_compile_options (-Wredundant-decls)
    add_compile_options (-Wshadow)
    add_compile_options (-Wstrict-prototypes)
    add_compile_options (-Wswitch-default)
    add_compile_options (-Wuninitialized)
    add_compile_options (-Wunreachable-code)
    add_compile_options (-Wunused)
    add_compile_options (-Wvarargs)
    add_compile_options (-Wwrite-strings)
    add_compile_options (-fstrict-aliasing)
    add_compile_options (-fstrict-overflow)
    add_compile_options (-funsafe-loop-optimizations)
    add_compile_options (-fvisibility=hidden)
    add_compile_options (-pedantic)
    add_compile_options (-pipe)
    add_compile_options (-std=c99)
    ## We'll update the samples to use any changed APIs.
    add_compile_options (-Wno-deprecated-declarations)

    ## Release
    if (CMAKE_BUILD_TYPE_LOWER STREQUAL "release")
        add_compile_options (-O3)
        add_compile_options (-DNDEBUG)
        add_compile_options (-D_FORTIFY_SOURCE=2)
        add_compile_options (-fdata-sections)
        add_compile_options (-ffunction-sections)
        add_compile_options (-Werror)

        if ("${CMAKE_SYSTEM_NAME_LOWER}" STREQUAL "darwin")
            add_compile_options (-Wl,-dead_strip)
        else ()
            add_compile_options (-Wl,--gc-sections)
        endif ()

    ## Debug
    elseif (CMAKE_BUILD_TYPE_LOWER STREQUAL "debug")
        add_compile_options (-UNDEBUG)
        add_compile_options (-O0)
        add_compile_options (-Wstrict-overflow=4)  # There are numerous posts on how this doesn't play well with -O3.

    ## Analysis
    elseif (CMAKE_BUILD_TYPE_LOWER STREQUAL "analysis")
        add_compile_options (-DNDEBUG)
        add_compile_options (-O0)
        add_compile_options (-Wstrict-overflow=4)
    endif ()

    ## Platform specific stuff
    if (("${CMAKE_SYSTEM_NAME_LOWER}" MATCHES "linux|windows|cygwin"))
        add_compile_options (-D_GNU_SOURCE=1)
    endif ()

    if (NOT ("${CMAKE_SYSTEM_NAME_LOWER}" MATCHES "cygwin"))
        # Cygwin warns you that -fPIC isn't necessary. That doesn't mix well
        # with -Werror unfortunately.
        add_compile_options (-fPIC)
    endif ()

    if (NOT BUILD_SERVER)
        add_compile_options (-fdiagnostics-color=always)
    endif ()

endif ()

if (("${CMAKE_SYSTEM_NAME_LOWER}" MATCHES "cygwin|windows"))
    # There's no remove_compile_options(), and MSys/Cygwin can't do this.
    add_compile_options (-fno-stack-protector)
    add_compile_options (-D__USE_MINGW_ANSI_STDIO=1)
endif ()
