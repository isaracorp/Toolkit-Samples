/** @file main.c
 *
 * @brief Display the toolkit's version information.
 *
 * @copyright Copyright (C) 2016-2021, ISARA Corporation, All Rights Reserved.
 *
 * @license Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * <a href="http://www.apache.org/licenses/LICENSE-2.0">http://www.apache.org/licenses/LICENSE-2.0</a>
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>

#include "iqr_retval.h"
#include "iqr_version.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Demonstrate using the APIs from iqr_version.h.
// ---------------------------------------------------------------------------------------------------------------------------------

int main(int argc, const char **argv)
{
    // Unused arguments.
    (void)argc;
    (void)argv;

    printf("Header version: %d.%d\n", IQR_VERSION_MAJOR, IQR_VERSION_MINOR);
    printf("                %s\n", IQR_VERSION_STRING);

    int exit_value = EXIT_SUCCESS;
    iqr_retval ret = iqr_VersionCheck(IQR_VERSION_MAJOR, IQR_VERSION_MINOR);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_VersionCheck(): %s\n", iqr_StrError(ret));
        exit_value = EXIT_FAILURE;
    } else {
        printf("Header version matches library version.\n");
    }

    const char *build_target = NULL;
    ret = iqr_VersionGetBuildTarget(&build_target);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_VersionGetBuildTarget(): %s\n", iqr_StrError(ret));
        exit_value = EXIT_FAILURE;
    } else {
        printf("Library build target: %s\n", build_target);
    }

    const char *build_hash = NULL;
    ret = iqr_VersionGetBuildHash(&build_hash);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_VersionGetBuildHash(): %s\n", iqr_StrError(ret));
        exit_value = EXIT_FAILURE;
    } else {
        printf("Library build hash:\n    %s\n", build_hash);
    }

    return exit_value;
}
