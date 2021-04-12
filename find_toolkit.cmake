# Copyright (C) 2016-2021, ISARA Corporation
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

if (NOT "${IQR_TOOLKIT_ROOT}" STREQUAL "")
    if (NOT "$ENV{IQR_TOOLKIT_ROOT}" STREQUAL "")
        message (WARNING "IQR_TOOLKIT_ROOT environment and cmake (possibly cached?) variables both set, using cmake variable.")
    endif ()
    message (STATUS "Toolkit directory from cmake variable: ${IQR_TOOLKIT_ROOT}")
elseif (NOT "$ENV{IQR_TOOLKIT_ROOT}" STREQUAL "")
    message (STATUS "Toolkit include directory from environment variable: $ENV{IQR_TOOLKIT_ROOT}")
    set (IQR_TOOLKIT_ROOT "$ENV{IQR_TOOLKIT_ROOT}")
else ()
    message (STATUS "IQR_TOOLKIT_ROOT environment or cmake variables not set, trying: ${CMAKE_CURRENT_LIST_DIR}/../")
    set (IQR_TOOLKIT_ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
endif ()

include_directories ("${IQR_TOOLKIT_ROOT}/include")

if (NOT IQR_TOOLKIT_LIB_DIR)
    set (IQR_TOOLKIT_LIB_DIR ${IQR_TOOLKIT_ROOT}/lib)
    message(STATUS "IQR_TOOLKIT_LIB_DIR not specified, setting to default: ${IQR_TOOLKIT_LIB_DIR}")
endif ()

set (CMAKE_FIND_LIBRARY_PREFIXES "lib")
string (TOLOWER "${CMAKE_SYSTEM_NAME}" CMAKE_SYSTEM_NAME_LOWER)
if ("${CMAKE_SYSTEM_NAME_LOWER}" MATCHES "windows")
    if (STATIC)
        set (CMAKE_FIND_LIBRARY_SUFFIXES "_static.lib")
    else ()
        set (CMAKE_FIND_LIBRARY_SUFFIXES ".lib")
    endif ()
else ()
    if (STATIC)
        set (CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    else ()
        set (CMAKE_FIND_LIBRARY_SUFFIXES ".so;.dylib")
    endif ()
endif ()

find_library (IQR_TOOLKIT_LIB
    NAMES iqr_toolkit
    PATHS "${IQR_TOOLKIT_LIB_DIR}"
    NO_CMAKE_FIND_ROOT_PATH
    REQUIRED
    )

if (NOT TARGET iqr_toolkit)
    add_library(iqr_toolkit UNKNOWN IMPORTED)
    set_target_properties(iqr_toolkit PROPERTIES IMPORTED_LOCATION ${IQR_TOOLKIT_LIB})
endif ()

message (STATUS "Found the ISARA Toolkit library: ${IQR_TOOLKIT_LIB}")
