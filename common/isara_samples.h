/** @file isara_samples.h
 *
 * @brief Common functionality for the ISARA samples.
 *
 * @copyright Copyright (C) 2018-2019, ISARA Corporation
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

#include <stdint.h>
#include <stdlib.h>

#include "iqr_retval.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Security functions.
// ---------------------------------------------------------------------------------------------------------------------------------

/** Securely wipe a memory buffer.
 *
 * This function overwrites @a len bytes of the buffer @a b with 0x00 values
 * using an implementation that won't be optimized out of code.
 *
 * @param b     Pointer to a memory buffer.
 * @param len   The size of the buffer in bytes.
 */
void secure_memzero(void *b, size_t len);

// ---------------------------------------------------------------------------------------------------------------------------------
// Common I/O functions.
// ---------------------------------------------------------------------------------------------------------------------------------

/** Write the given buffer to the named file.
 *
 * @param fname     Name of the file.
 * @param data      Pointer to a data buffer.
 * @param data_size Size of @a data in bytes.
 */
iqr_retval save_data(const char *fname, const uint8_t *data, size_t data_size);

/** Load a named file into a buffer.
 *
 * This function allocates the buffer; be sure to secure_memzero() it when
 * you're done with it if it contains cryptographic information. You must
 * free() the @a data buffer when you're done with it.
 *
 * @param fname     Name of the file.
 * @param data      A pointer that will receive the buffer's pointer.
 * @param data_size A pointer to the size of @a data in bytes.
 */
iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size);

// ---------------------------------------------------------------------------------------------------------------------------------
// Parameter parsing.
// ---------------------------------------------------------------------------------------------------------------------------------

/** Tests if two parameters match.
 *
 * Parameters are expected to be less than 32 characters in length.
 *
 * @param p1    First parameter string.
 * @param p2    Second parameter string.
 *
 * @return 0 if the two parameters match, non-zero otherwise.
 */
int paramcmp(const char *p1 , const char *p2);
