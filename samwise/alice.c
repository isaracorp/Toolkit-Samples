/** @file alice.c
 *
 * @brief Functions to demonstrate how Alice (the initiator) should use Samwise.
 *
 * Alice is treated as a pseudo-separate process. She has her own params and
 * appears to keep her own state. It is done like this to show how the "Alice"
 * side of the transaction can be performed independent of Bob.
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
#include <stdio.h>
#include <stdlib.h>

#include "iqr_samwise.h"
#include "iqr_retval.h"
#include "iqr_rng.h"
#include "isara_samples.h"

/* In a real program, you wouldn't make these global variables. It's not thread
 * safe. It would be better to pass this around as required. It is done this
 * way to facilitate the pseudo-separate process paradigm.
 */
static iqr_SamwiseParams *params;
static iqr_SamwiseInitiatorPrivateKey *initiator_private_key;

iqr_retval init_alice(const iqr_Context *ctx, const iqr_SamwiseVariant *variant)
{
    if (ctx == NULL) {
        fprintf(stderr, "Context was null.\n");
        return IQR_ENULLPTR;
    }

    if (variant == NULL) {
        fprintf(stderr, "Variant was null.\n");
        return IQR_ENULLPTR;
    }

    iqr_retval ret = iqr_SamwiseCreateParams(ctx, variant, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SamwiseCreateParams(): %s\n", iqr_StrError(ret));
    }
    return ret;
}

iqr_retval alice_start(const iqr_RNG *rng, bool dump)
{
    if (rng == NULL) {
        fprintf(stderr, "The RNG was null and we really need that RNG\n");
        return IQR_ENULLPTR;
    }

    size_t initiator_size = IQR_SAMWISE_INITIATOR_PUBLIC_KEY_SIZE;
    uint8_t *initiator_public_key = calloc(1, initiator_size);
    if (initiator_public_key == NULL) {
        fprintf(stderr, "We seem to have run out of memory. ret=%d\n", errno);
        return IQR_ENOMEM;
    }

    iqr_retval ret = iqr_SamwiseCreateInitiatorPrivateKey(params, rng, &initiator_private_key);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SamwiseCreateInitiatorPrivateKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = iqr_SamwiseGetInitiatorPublicKey(initiator_private_key, rng, initiator_public_key, initiator_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SamwiseGetInitiatorPublicKey(): %s\n", iqr_StrError(ret));
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
        iqr_SamwiseDestroyInitiatorPrivateKey(&initiator_private_key);
    }
    free(initiator_public_key);
    return ret;
}

iqr_retval alice_get_secret(uint8_t *secret, size_t secret_size)
{
    iqr_retval ret = IQR_OK;
    uint8_t *responder_public_key = NULL;

    if (secret == NULL || secret_size != IQR_SAMWISE_SECRET_SIZE) {
        fprintf(stderr, "The input parameters were bad.\n");
        ret = IQR_ENULLPTR;
        goto end;
    }

    size_t responder_size = IQR_SAMWISE_RESPONDER_PUBLIC_KEY_SIZE;
    responder_public_key = calloc(1, responder_size);
    if (responder_public_key == NULL) {
        fprintf(stderr, "We seem to have run out of memory. ret=%d\n", errno);
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = receive_from_bob(responder_public_key, responder_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "We couldn't get the responder key from Bob.\n");
        goto end;
    }

    ret = iqr_SamwiseGetInitiatorSecret(initiator_private_key, responder_public_key, responder_size, secret, secret_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SamwiseGetInitiatorSecret(): %s\n", iqr_StrError(ret));
        goto end;
    }

end:
    free(responder_public_key);
    iqr_SamwiseDestroyInitiatorPrivateKey(&initiator_private_key);

    return ret;
}

iqr_retval cleanup_alice(void)
{
    iqr_retval ret = iqr_SamwiseDestroyParams(&params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SamwiseDestroyParams(): %s\n", iqr_StrError(ret));
    }
    return ret;
}
