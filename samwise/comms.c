/** @file comms.c
 *
 * @brief A fake communication channel used for communication between the
 * fabricated Alice and Bob. Meant to act as a network or other communication
 * channel to help demonstrate the process of key establishment.
 *
 * Quick suggestion, don't look too deeply into this file. It is not an example
 * of how to write good clean code. It is merely a stub required to help users
 * understand the data flow of Samwise. Again, don't read this file! You're
 * going to read it anyway aren't you...
 *
 * @copyright Copyright (C) 2019-2021, ISARA Corporation, All Rights Reserved.
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

#include "internal.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iqr_samwise.h"

#define NUM_TRANSACTIONS    2
#define MAX_PAYLOAD_BYTES   16000  // The largest key size used in Samwise is 15632 bytes.

/* Alice sends initiator public key and is stored in index 0.
 * Bob sends responder public key and is stored in index 1.
 */
#define ALICE_KEY_INDEX    0
#define BOB_KEY_INDEX      1

static uint8_t *simulated_network_bufs[NUM_TRANSACTIONS];

iqr_retval init_comms(void)
{
    for (int i = 0; i < NUM_TRANSACTIONS; i++) {
        simulated_network_bufs[i] = calloc(1, MAX_PAYLOAD_BYTES);
        if (simulated_network_bufs[i] == NULL) {
            fprintf(stderr, "MEMORY ERROR!!!. ret=%d\n", errno);
            return IQR_ENOMEM;
        }
    }
    return IQR_OK;
}

void cleanup_comms(void)
{
    for (int i = 0; i < NUM_TRANSACTIONS; i++) {
        free(simulated_network_bufs[i]);
    }
}

/* Bob sends responder public key to alice */
iqr_retval send_to_alice(uint8_t *buf, size_t size)
{
    if (size > MAX_PAYLOAD_BYTES) {
        fprintf(stderr, "Alice cannot store that much data.\n");
        return IQR_EBADVALUE;
    }
    memcpy(simulated_network_bufs[BOB_KEY_INDEX], buf, size);
    return IQR_OK;
}

iqr_retval send_to_bob(uint8_t *buf, size_t size)
{
    if (size > MAX_PAYLOAD_BYTES) {
        fprintf(stderr, "Bob cannot store that much data.\n");
        return IQR_EBADVALUE;
    }
    memcpy(simulated_network_bufs[ALICE_KEY_INDEX], buf, size);
    return IQR_OK;
}

iqr_retval receive_from_alice(uint8_t *buf, size_t size)
{
    if (size > MAX_PAYLOAD_BYTES) {
        fprintf(stderr, "Alice won't send that much data.\n");
        return IQR_EBADVALUE;
    }
    memcpy(buf, simulated_network_bufs[ALICE_KEY_INDEX], size);
    return IQR_OK;
}

iqr_retval receive_from_bob(uint8_t *buf, size_t size)
{
    if (size > MAX_PAYLOAD_BYTES) {
        fprintf(stderr, "Bob won't send that much data.\n");
        return IQR_EBADVALUE;
    }
    memcpy(buf, simulated_network_bufs[BOB_KEY_INDEX], size);
    return IQR_OK;
}
