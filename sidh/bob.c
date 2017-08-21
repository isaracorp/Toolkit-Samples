/** @file bob.c Functions to demonstrate how Bob should use SIDH.
 *
 * Bob is treated as a pseudo-separate process. He has his own params and
 * appears to keep his own state. It is done like this to show how the "Bob"
 * side of the transaction can be performed independent of Alice.
 *
 * @copyright Copyright 2017 ISARA Corporation
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
#include "iqr_sidh.h"

/* It is not suggested to make these global variables. It's not thread safe.
 * It would be better to pass this around as required. It is done this way to
 * facilitate the pseudo-separate process paradigm.
 */
static iqr_SIDHParams *params;
static iqr_SIDHBobPrivateKey *bob_private_key;

iqr_retval init_bob(const iqr_Context *ctx)
{
    if (ctx == NULL) {
        fprintf(stderr, "Context was null, somehow.\n");
        return IQR_ENULLPTR;
    }

    iqr_retval ret = iqr_SIDHCreateParams(ctx, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIDHCreateParams(): %s\n", iqr_StrError(ret));
    }
    return ret;
}

iqr_retval bob_start(const iqr_RNG *rng, bool dump)
{
    if (rng == NULL) {
        fprintf(stderr, "The RNG was NULL and we really need that RNG.\n");
        return IQR_ENULLPTR;
    }

    size_t bob_size = IQR_SIDH_BOB_PUBLIC_KEY_SIZE;
    uint8_t *bob_public_key = calloc(1, bob_size);
    if (bob_public_key == NULL) {
        fprintf(stderr, "Couldn't find more memory. ret=%d\n", errno);
        return IQR_ENOMEM;
    }

    iqr_retval ret = iqr_SIDHCreateBobPrivateKey(params, rng, &bob_private_key);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIDHCreateBobPrivateKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = iqr_SIDHGetBobPublicKey(bob_private_key, bob_public_key, bob_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIDHGetBobPublicKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    if (dump) {
        ret = save_data(BOB_KEY_FNAME, bob_public_key, bob_size);
        if (ret != IQR_OK) {
            goto end;
        }
    }

    ret = send_to_alice(bob_public_key, bob_size);

end:
    if (ret != IQR_OK) {
        iqr_SIDHDestroyBobPrivateKey(&bob_private_key);
    }
    free(bob_public_key);
    return ret;
}

iqr_retval bob_get_secret(uint8_t *secret, size_t secret_size)
{
    iqr_retval ret = IQR_OK;
    uint8_t *alice_public_key = NULL;

    if (secret == NULL || secret_size != IQR_SIDH_SECRET_SIZE) {
        fprintf(stderr, "The input parameters were bad.\n");
        ret = IQR_ENULLPTR;
        goto end;
    }

    size_t alice_size = IQR_SIDH_ALICE_PUBLIC_KEY_SIZE;
    alice_public_key = calloc(1, alice_size);
    if (alice_public_key == NULL) {
        fprintf(stderr, "We seem to have run out of memory. ret=%d\n", errno);
        ret = IQR_ENOMEM;
    }

    ret = receive_from_alice(alice_public_key, &alice_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "We couldn't get Alice's public key.\n");
        goto end;
    }

    ret = iqr_SIDHGetBobSecret(bob_private_key, alice_public_key, alice_size, secret, secret_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIDHGetBobSecret(): %s\n", iqr_StrError(ret));
        goto end;
    }

end:
    free(alice_public_key);
    iqr_SIDHDestroyBobPrivateKey(&bob_private_key);
    return ret;
}

iqr_retval cleanup_bob(void)
{
    iqr_retval ret = iqr_SIDHDestroyParams(&params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIDHDestroyParams(): %s\n", iqr_StrError(ret));
    }
    return ret;
}
