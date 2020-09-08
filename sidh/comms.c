/** @file comms.c
 *
 * @brief A fake communication channel used for communication between the
 * fabricated Alice and Bob. Meant to act as a network or other communication
 * channel to help demonstrate the process of key establishment.
 *
 * Quick suggestion, don't look too deeply into this file. It is not an example
 * of how to write good clean code. It is merely a stub required to help users
 * understand the data flow of SIDH. Again, don't read this file! You're
 * going to read it anyway aren't you...
 *
 * @copyright Copyright (C) 2017-2020, ISARA Corporation
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

#include "iqr_sidh.h"

#define NUM_TRANSACTIONS    2
#define MAX_PAYLOAD_BYTES   564

/* Alice sends her public key stored in index 0.
 * Bob sends his public key stored in index 1.
 */
#define ALICE_KEY_INDEX    0
#define BOB_KEY_INDEX      1

struct com_buf {
    uint8_t *data;
    size_t size;
};

static struct com_buf simulated_network_bufs[NUM_TRANSACTIONS];

iqr_retval init_comms(void)
{
    for (int i = 0; i < NUM_TRANSACTIONS; i++) {
        simulated_network_bufs[i].data = calloc(1, MAX_PAYLOAD_BYTES);
        if (simulated_network_bufs[i].data == NULL) {
            fprintf(stderr, "MEMORY ERROR!!!. ret=%d\n", errno);
            return IQR_ENOMEM;
        }
        simulated_network_bufs[i].size = 0;
    }
    return IQR_OK;
}

void cleanup_comms(void)
{
    for (int i = 0; i < NUM_TRANSACTIONS; i++) {
        free(simulated_network_bufs[i].data);
    }
}

iqr_retval send_to_alice(uint8_t *buf, size_t size)
{
    if (size > MAX_PAYLOAD_BYTES) {
        fprintf(stderr, "Need less bytes.\n");
        return IQR_EBADVALUE;
    }

    memcpy(simulated_network_bufs[BOB_KEY_INDEX].data, buf, size);
    simulated_network_bufs[BOB_KEY_INDEX].size = size;
    return IQR_OK;
}

iqr_retval send_to_bob(uint8_t *buf, size_t size)
{
    if (size > MAX_PAYLOAD_BYTES) {
        fprintf(stderr, "Bob cannot store that much data.\n");
        return IQR_EBADVALUE;
    }

    memcpy(simulated_network_bufs[ALICE_KEY_INDEX].data, buf, size);
    simulated_network_bufs[ALICE_KEY_INDEX].size = size;
    return IQR_OK;
}

iqr_retval receive_from_alice(uint8_t *buf, size_t *size)
{
    if (*size > MAX_PAYLOAD_BYTES) {
        fprintf(stderr, "That buffer is a tad on the large side.\n");
        return IQR_EBADVALUE;
    }

    memcpy(buf, simulated_network_bufs[ALICE_KEY_INDEX].data, simulated_network_bufs[ALICE_KEY_INDEX].size);
    *size = simulated_network_bufs[ALICE_KEY_INDEX].size;
    return IQR_OK;
}

iqr_retval receive_from_bob(uint8_t *buf, size_t *size)
{
    if (*size > MAX_PAYLOAD_BYTES) {
        fprintf(stderr, "You want too many bytes, don't be greedy.\n");
        return IQR_EBADVALUE;
    }

    memcpy(buf, simulated_network_bufs[BOB_KEY_INDEX].data, simulated_network_bufs[BOB_KEY_INDEX].size);
    *size = simulated_network_bufs[BOB_KEY_INDEX].size;
    return IQR_OK;
}
