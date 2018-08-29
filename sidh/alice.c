/** @file alice.c
 *
 * @brief Functions to demonstrate how Alice should use SIDH.
 *
 * Alice is treated as a pseudo-separate process. She has her own params and
 * appears to keep her own state. It is done like this to show how the "Alice"
 * side of the transaction can be performed independent of Bob.
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

#include "iqr_retval.h"
#include "iqr_rng.h"
#include "iqr_sidh.h"

/* It is not suggested to make these global variables. It's not thread safe.
 * It would be better to pass this around as required. It is done this way to
 * facilitate the pseudo-separate process paradigm.
 */
static iqr_SIDHParams *params;
static iqr_SIDHAlicePrivateKey *alice_private_key;

iqr_retval init_alice(const iqr_Context *ctx, const iqr_SIDHVariant *variant, size_t *secret_size)
{
    if (ctx == NULL || variant == NULL || secret_size == NULL) {
        fprintf(stderr, "Context was null.\n");
        return IQR_ENULLPTR;
    }

    iqr_retval ret = iqr_SIDHCreateParams(ctx, variant, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIDHCreateParams(): %s\n", iqr_StrError(ret));
        return ret;
    }

    ret = iqr_SIDHGetSecretSize(params, secret_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIDHGetSecretSize(): %s\n", iqr_StrError(ret));
    }
    return ret;
}

iqr_retval alice_start(const iqr_RNG *rng, bool dump)
{
    if (rng == NULL) {
        fprintf(stderr, "The RNG was NULL and we really need that RNG.\n");
        return IQR_ENULLPTR;
    }

    size_t alice_size = 0;
    iqr_retval ret = iqr_SIDHGetPublicKeySize(params, &alice_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIDHGetPublicKeySize(): %s\n", iqr_StrError(ret));
        return ret;
    }

    uint8_t *alice_public_key = calloc(1, alice_size);
    if (alice_public_key == NULL) {
        fprintf(stderr, "We seem to have run out of memory. ret=%d\n", errno);
        return IQR_ENOMEM;
    }

    ret = iqr_SIDHCreateAlicePrivateKey(params, rng, &alice_private_key);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIDHCreateAlicePrivateKey(): %s\n", iqr_StrError(ret));
        goto end;
    }
    ret = iqr_SIDHGetAlicePublicKey(alice_private_key, alice_public_key, alice_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIDHGetAlicePublicKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    if (dump) {
        ret = save_data(ALICE_KEY_FNAME, alice_public_key, alice_size);
        if (ret != IQR_OK) {
            goto end;
        }
    }

    ret = send_to_bob(alice_public_key, alice_size);

end:
    if (ret != IQR_OK) {
        iqr_SIDHDestroyAlicePrivateKey(&alice_private_key);
    }
    free(alice_public_key);
    return ret;
}

iqr_retval alice_get_secret(uint8_t *secret, size_t secret_size)
{
    iqr_retval ret = IQR_OK;
    uint8_t *bob_public_key = NULL;

    if (secret == NULL) {
        fprintf(stderr, "The input parameters were bad.\n");
        return IQR_ENULLPTR;
    }

    size_t bob_size = 0;
    ret = iqr_SIDHGetPublicKeySize(params, &bob_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIDHGetPublicKeySize(): %s\n", iqr_StrError(ret));
        return ret;
    }

    bob_public_key = calloc(1, bob_size);
    if (bob_public_key == NULL) {
        fprintf(stderr, "We seem to have run out of memory. ret=%d\n", errno);
        return  IQR_ENOMEM;
    }

    ret = receive_from_bob(bob_public_key, &bob_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "We couldn't get Bob's public key.\n");
        goto end;
    }

    ret = iqr_SIDHGetAliceSecret(alice_private_key, bob_public_key, bob_size, secret, secret_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIDHGetAliceSecret(): %s\n", iqr_StrError(ret));
        goto end;
    }

end:
    free(bob_public_key);
    iqr_SIDHDestroyAlicePrivateKey(&alice_private_key);

    return ret;
}

iqr_retval cleanup_alice(void)
{
    iqr_retval ret = iqr_SIDHDestroyParams(&params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_SIDHDestroyParams(): %s\n", iqr_StrError(ret));
    }
    return ret;
}
