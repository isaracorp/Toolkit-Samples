/** @file alice.c Functions to demonstrate how Alice (the initiator) should
 * use NewHope.
 *
 * Alice is treated as a pseudo-separate process. She has her own params and
 * appears to keep her own state. It is done like this to show how the "Alice"
 * side of the transaction can be performed independent of Bob.
 *
 * @copyright Copyright 2016 ISARA Corporation
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
#include <stdio.h>
#include <stdlib.h>

#include "iqr_retval.h"
#include "iqr_rng.h"

/* It is not suggested to make these global variables. It's not thread safe.
 * It would be better to pass this around as required. It is done this way to
 * facilitate the pseudo-separate process paradigm.
 */
static iqr_NewHopeParams *params;
static iqr_NewHopeInitiator *initiator_private_key;

iqr_retval init_alice(const iqr_Context *ctx, const iqr_NewHopeVariant *variant)
{
    if (ctx == NULL) {
        fprintf(stderr, "Context was null.\n");
        return IQR_ENULLPTR;
    }

    iqr_retval ret = iqr_NewHopeCreateParams(ctx, variant, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_NewHopeCreateParams(): %s\n", iqr_StrError(ret));
    }
    return ret;
}

iqr_retval alice_start(const iqr_RNG *rng, bool dump)
{
    if (rng == NULL) {
        fprintf(stderr, "The RNG was null and we really need that RNG\n");
        return IQR_ENULLPTR;
    }

    size_t initiator_size = IQR_NEWHOPE_INITIATOR_KEY_SIZE;
    uint8_t *initiator_public_key = calloc(1, initiator_size);
    if (initiator_public_key == NULL) {
        fprintf(stderr, "We seem to have run out of memory. ret=%d\n", errno);
        return IQR_ENOMEM;
    }

    iqr_retval ret = iqr_NewHopeCreateInitiatorPrivateKey(params, &initiator_private_key);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_NewHopeCreateInitiatorPrivateKey(): %s\n", iqr_StrError(ret));
        goto end;
    }
    ret = iqr_NewHopeCreateInitiatorPublicKey(params, rng, initiator_private_key, initiator_public_key, initiator_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_NewHopeCreateInitiatorPublicKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    if (dump) {
        ret = save_data(ALICE_KEY_FNAME, initiator_public_key, initiator_size);
        if (ret != IQR_OK) {
            goto end;
        }
    }

    ret = send_to_bob(initiator_public_key, initiator_size);

end:
    if (ret != IQR_OK) {
        iqr_NewHopeDestroyInitiatorPrivateKey(&initiator_private_key);
    }
    free(initiator_public_key);
    return ret;
}

iqr_retval alice_get_secret(uint8_t *secret, size_t secret_size)
{
    if (secret == NULL || secret_size != IQR_NEWHOPE_SECRET_SIZE) {
        fprintf(stderr, "The input parameters were bad.\n");
        return IQR_ENULLPTR;
    }

    size_t responder_size = IQR_NEWHOPE_RESPONDER_KEY_SIZE;
    uint8_t *responder_public_key = calloc(1, responder_size);
    if (responder_public_key == NULL) {
        fprintf(stderr, "We seem to have run out of memory. ret=%d\n", errno);
        return IQR_ENOMEM;
    }

    iqr_retval ret = receive_from_bob(responder_public_key, &responder_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "We couldn't get the responder key from Bob.\n");
        goto end;
    }

    ret = iqr_NewHopeGetInitiatorSecret(params, responder_public_key, responder_size, initiator_private_key, secret,
        secret_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_NewHopeGetInitiatorSecret(): %s\n", iqr_StrError(ret));
        goto end;
    }

end:
    ret = iqr_NewHopeDestroyInitiatorPrivateKey(&initiator_private_key);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_NewHopeDestroyInitiatorPrivateKey(): %s\n", iqr_StrError(ret));
    }

    free(responder_public_key);
    return ret;
}

iqr_retval cleanup_alice(void)
{
    iqr_retval ret = iqr_NewHopeDestroyParams(&params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_NewHopeDestroyParams(): %s\n", iqr_StrError(ret));
    }
    return ret;
}
