/** @file bob.c Functions to demonstrate how Bob (the responder) should
 * use NewHope.
 *
 * Bob is treated as a pseudo-separate process. He has his own params and
 * appears to keep his own state. It is done like this to show how the "Bob"
 * side of the transaction can be performed independent of Alice.
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
static iqr_NewHopeResponder *responder_private_key;

iqr_retval init_bob(const iqr_Context *ctx, const iqr_NewHopeVariant *variant)
{
    if (ctx == NULL) {
        fprintf(stderr, "Context was null, somehow.\n");
        return IQR_ENULLPTR;
    }

    iqr_retval ret = iqr_NewHopeCreateParams(ctx, variant, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_NewHopeCreateParams(): %s\n", iqr_StrError(ret));
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
    size_t initiator_size = IQR_NEWHOPE_INITIATOR_KEY_SIZE;
    uint8_t *initiator_public_key = calloc(1, initiator_size);
    if (initiator_public_key == NULL) {
        fprintf(stderr, "We seem to have run out of memory. ret=%d\n", errno);
        return IQR_ENOMEM;
    }

    iqr_retval ret = receive_from_alice(initiator_public_key, &initiator_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "We couldn't get the initiator key from Alice.\n");
        goto end;
    }

    size_t responder_size = IQR_NEWHOPE_RESPONDER_KEY_SIZE;
    responder_public_key = calloc(1, responder_size);
    if (responder_public_key == NULL) {
        fprintf(stderr, "Couldn't find more memory. ret=%d\n", errno);
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_NewHopeCreateResponderPrivateKey(params, &responder_private_key);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_NewHopeCreateResponderPrivateKey(): %s\n", iqr_StrError(ret));
        goto end;
    }
    ret = iqr_NewHopeCreateResponderPublicKey(params, rng, initiator_public_key, initiator_size,
        responder_private_key, responder_public_key, responder_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_NewHopeCreateResponderPublicKey(): %s\n", iqr_StrError(ret));
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
    free(responder_public_key);
    free(initiator_public_key);
    if (ret != IQR_OK) {
        iqr_NewHopeDestroyResponderPrivateKey(&responder_private_key);
    }
    return ret;
}

iqr_retval bob_get_secret(uint8_t *secret, size_t secret_size)
{
    if (secret == NULL) {
        return IQR_ENULLPTR;
    }
    if (secret_size != IQR_NEWHOPE_SECRET_SIZE) {
        fprintf(stderr, "The input parameters were bad.\n");
        return IQR_EBADVALUE;
    }

    iqr_retval ret = iqr_NewHopeGetResponderSecret(params, responder_private_key, secret, secret_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_NewHopeGetResponderSecret(): %s\n", iqr_StrError(ret));
        return ret;
    }
    ret = iqr_NewHopeDestroyResponderPrivateKey(&responder_private_key);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_NewHopeDestroyResponderPrivateKey(): %s\n", iqr_StrError(ret));
    }
    return ret;
}

iqr_retval cleanup_bob(void)
{
    iqr_retval ret = iqr_NewHopeDestroyParams(&params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_NewHopeDestroyParams(): %s\n", iqr_StrError(ret));
    }
    return ret;
}
