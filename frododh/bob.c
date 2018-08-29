/** @file bob.c
 *
 * @brief Functions to demonstrate how Bob (the responder) should use FrodoDH.
 *
 * Bob is treated as a pseudo-separate process. He has his own params and
 * appears to keep his own state. It is done like this to show how the "Bob"
 * side of the transaction can be performed independent of Alice.
 *
 * @copyright Copyright 2017-2018 ISARA Corporation
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

#include "iqr_frododh.h"
#include "iqr_retval.h"
#include "iqr_rng.h"

/* It is not suggested to make these global variables. It's not thread safe.
 * It would be better to pass this around as required. It is done this way to
 * facilitate the pseudo-separate process paradigm.
 */
static iqr_FrodoDHParams *params;
static iqr_FrodoDHResponderPrivateKey *responder_private_key;

iqr_retval init_bob(const iqr_Context *ctx, const iqr_FrodoDHVariant *variant)
{
    if (ctx == NULL) {
        fprintf(stderr, "Context was null, somehow.\n");
        return IQR_ENULLPTR;
    }

    if (variant == NULL) {
        fprintf(stderr, "Variant was null, somehow.\n");
        return IQR_ENULLPTR;
    }

    iqr_retval ret = iqr_FrodoDHCreateParams(ctx, variant, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_FrodoDHCreateParams(): %s\n", iqr_StrError(ret));
    }
    return ret;
}

iqr_retval bob_start(const iqr_RNG *rng, bool dump)
{
    if (rng == NULL) {
        fprintf(stderr, "The RNG was null and we really need that RNG\n");
        return IQR_ENULLPTR;
    }

    uint8_t *responder_public_key = NULL;

    size_t initiator_size = 0;
    iqr_retval ret = iqr_FrodoDHGetInitiatorPublicKeySize(params, &initiator_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_FrodoDHGetInitiatorPublicKeySize(): %s\n", iqr_StrError(ret));
        return ret;
    }

    uint8_t *initiator_public_key = calloc(1, initiator_size);
    if (initiator_public_key == NULL) {
        fprintf(stderr, "We seem to have run out of memory. ret=%d\n", errno);
        return IQR_ENOMEM;
    }

    ret = receive_from_alice(initiator_public_key, initiator_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "We couldn't get the initiator key from Alice.\n");
        goto end;
    }

    size_t responder_size = 0;
    ret = iqr_FrodoDHGetResponderPublicKeySize(params, &responder_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_FrodoDHGetResponderPublicKeySize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    responder_public_key = calloc(1, responder_size);
    if (responder_public_key == NULL) {
        fprintf(stderr, "Couldn't find more memory. ret=%d\n", errno);
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_FrodoDHCreateResponderPrivateKey(params, rng, &responder_private_key);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_FrodoDHCreateResponderPrivateKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = iqr_FrodoDHGetResponderPublicKey(responder_private_key, rng, initiator_public_key, initiator_size, responder_public_key,
        responder_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_FrodoDHGetResponderPublicKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    if (dump) {
        ret = save_data(BOB_KEY_FNAME, responder_public_key, responder_size);
        if (ret != IQR_OK) {
            goto end;
        }
    }

    ret = send_to_alice(responder_public_key, responder_size);

end:
    if (ret != IQR_OK) {
        iqr_FrodoDHDestroyResponderPrivateKey(&responder_private_key);
    }
    free(responder_public_key);
    free(initiator_public_key);
    return ret;
}

iqr_retval bob_get_secret(uint8_t *secret, size_t secret_size)
{
    iqr_retval ret = IQR_OK;

    if (secret == NULL || secret_size != IQR_FRODODH_SECRET_SIZE) {
        fprintf(stderr, "The input parameters were bad.\n");
        ret = IQR_ENULLPTR;
        goto end;
    }

    ret = iqr_FrodoDHGetResponderSecret(responder_private_key, secret, secret_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_FrodoDHGetResponderSecret(): %s\n", iqr_StrError(ret));
        goto end;
    }

end:
    iqr_FrodoDHDestroyResponderPrivateKey(&responder_private_key);
    return ret;
}

iqr_retval cleanup_bob(void)
{
    iqr_retval ret = iqr_FrodoDHDestroyParams(&params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_FrodoDHDestroyParams(): %s\n", iqr_StrError(ret));
    }
    return ret;
}
