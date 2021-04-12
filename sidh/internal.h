/** @file internal.h
 *
 * @brief Common header for the sample.
 *
 * @copyright Copyright (C) 2017-2021, ISARA Corporation, All Rights Reserved.
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

#ifndef INTERNAL_H
#define INTERNAL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "iqr_context.h"
#include "iqr_rng.h"
#include "iqr_sidh.h"

#define ALICE_KEY_FNAME     "alice_key.dat"
#define BOB_KEY_FNAME       "bob_key.dat"
#define ALICE_SECRET_FNAME  "alice_secret.dat"
#define BOB_SECRET_FNAME    "bob_secret.dat"

/* Alice related. */
iqr_retval init_alice(const iqr_Context *ctx, const iqr_SIDHVariant *variant, size_t *secret_size);
iqr_retval alice_start(const iqr_RNG *rng, bool dump);
iqr_retval alice_get_secret(uint8_t *secret, size_t secret_size);
iqr_retval cleanup_alice(void);

/* Bob related */
iqr_retval init_bob(const iqr_Context *ctx, const iqr_SIDHVariant *variant);
iqr_retval bob_start(const iqr_RNG *rng, bool dump);
iqr_retval bob_get_secret(uint8_t *secret, size_t secret_size);
iqr_retval cleanup_bob(void);

/* Comms related. */
iqr_retval init_comms(void);
iqr_retval send_to_alice(uint8_t *buf, size_t size);
iqr_retval send_to_bob(uint8_t *buf, size_t size);
iqr_retval receive_from_alice(uint8_t *buf, size_t *size);
iqr_retval receive_from_bob(uint8_t *buf, size_t *size);
void cleanup_comms(void);

#endif /* INTERNAL_H */
