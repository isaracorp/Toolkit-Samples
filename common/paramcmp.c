/** @file paramcmp.c
 *
 * @brief Test to see if two parameters match.
 *
 * @copyright Copyright (C) 2016-2020, ISARA Corporation
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

#include "isara_samples.h"

#include <stdlib.h>
#include <string.h>

// ---------------------------------------------------------------------------------------------------------------------------------
// Parameter parsing.
// ---------------------------------------------------------------------------------------------------------------------------------

int paramcmp(const char *p1 , const char *p2)
{
    if (p1 == NULL || p2 == NULL) {
        return -1;
    }

    const size_t max_param_size = 32;  // Arbitrary, but reasonable.

    if (strnlen(p1, max_param_size) != strnlen(p2, max_param_size)) {
        return 1;
    }

    return strncmp(p1, p2, max_param_size);
}
