# Copyright 2016-2018 ISARA Corporation
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
    message (WARNING "IQR_TOOLKIT_ROOT environment or cmake variables not set, trying: ${CMAKE_CURRENT_LIST_DIR}/../")
    set (IQR_TOOLKIT_ROOT "${CMAKE_CURRENT_LIST_DIR}/..")
endif ()

include_directories ("${IQR_TOOLKIT_ROOT}/include")
link_directories ("${IQR_TOOLKIT_ROOT}/lib")

# Find out which Edition we've got.
find_file (TOOLKIT_EDITION_LIB
    NAMES libiqr_toolkit.so libiqr_toolkit.a
    PATHS "${IQR_TOOLKIT_ROOT}/lib")
find_file (SIGNATURE_EDITION_LIB
    NAMES libiqr_toolkit_signature.so libiqr_toolkit_signature.a
    PATHS "${IQR_TOOLKIT_ROOT}/lib")
find_file (FIPS140_EDITION_LIB
    NAMES libiqr_toolkit_fips140.so
    PATHS "${IQR_TOOLKIT_ROOT}/lib")
if (TOOLKIT_EDITION_LIB)
    set (IQR_TOOLKIT_LIB iqr_toolkit)
elseif (SIGNATURE_EDITION_LIB)
    set (IQR_TOOLKIT_LIB iqr_toolkit_signature)
elseif (FIPS140_EDITION_LIB)
    set (IQR_TOOLKIT_LIB iqr_toolkit_fips140)
else ()
    message (ERROR "Unable to find the ISARA Radiate toolkit library.")
    set (IQR_TOOLKIT_LIB iqr_toolkit)
endif ()
