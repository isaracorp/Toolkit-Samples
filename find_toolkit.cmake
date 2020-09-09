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

# Find the toolkit.
find_library(TOOLKIT_LIB
    NAMES iqr_toolkit
    PATHS "${IQR_TOOLKIT_ROOT}/lib"
    NO_CMAKE_FIND_ROOT_PATH
    )

if (NOT TOOLKIT_LIB)
    message (FATAL_ERROR "Unable to find the ISARA Radiate toolkit library.")
endif ()

set (IQR_TOOLKIT_LIB iqr_toolkit)
