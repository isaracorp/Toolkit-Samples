# Copyright (C) 2016-2023, ISARA Corporation
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

# CMake or same-line/exported environment variables you need to use:
#
# * IQR_TOOLKIT_ROOT set to the IQR Toolkit's root directory.

cmake_minimum_required (VERSION 3.7)
cmake_policy (SET CMP0054 NEW)

project (chacha20_decrypt)

include (../../find_toolkit.cmake)
include (../../compiler_options.cmake)

include_directories (../../common)
if (NOT TARGET isara_samples)
    add_subdirectory(../../common common)
endif ()

add_executable (chacha20_decrypt main.c)
add_dependencies (chacha20_decrypt isara_samples)
target_link_libraries (chacha20_decrypt ${IQR_TOOLKIT_LIB} isara_samples)
