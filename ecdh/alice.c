/** @file alice.c Functions to demonstrate how Alice should use ECDH.
 *
 * Alice is treated as a pseudo-separate process. She has her own params and
 * appears to keep her own state. It is done like this to show how the "Alice"
 * side of the transaction can be performed independent of Bob.
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

#include "iqr_ecdh.h"
#include "iqr_retval.h"
#include "iqr_rng.h"

/* It is not suggested to make these global variables. It's not thread safe.
 * It would be better to pass this around as required. It is done this way to
 * facilitate the pseudo-separate process paradigm.
 */
static iqr_ECDHParams *params;
static iqr_ECDHPrivateKey *alice_private_key;
static uint8_t *alice_secret;

iqr_retval init_alice(const iqr_Context *ctx, const iqr_ECDHCurve *curve)
{
    if (ctx == NULL) {
        fprintf(stderr, "Context was null.\n");
        return IQR_ENULLPTR;
    }

    if (curve == NULL) {
        fprintf(stderr, "Curve was null.\n");
        return IQR_ENULLPTR;
    }

    iqr_retval ret = iqr_ECDHCreateParams(ctx, curve, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_ECDHCreateParams(): %s\n", iqr_StrError(ret));
    }
    return ret;
}

iqr_retval alice_start(const iqr_RNG *rng, bool dump)
{
    if (rng == NULL) {
        fprintf(stderr, "The RNG was null and we really need that RNG\n");
        return IQR_ENULLPTR;
    }

    size_t alice_public_key_size = 0;
    iqr_retval ret = iqr_ECDHGetPublicKeySize(params, &alice_public_key_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_ECDHGetPublicKeySize(): %s\n", iqr_StrError(ret));
        return ret;
    }

    uint8_t *alice_public_key = calloc(1, alice_public_key_size);
    if (alice_public_key == NULL) {
        fprintf(stderr, "We seem to have run out of memory. ret=%d\n", errno);
        return IQR_ENOMEM;
    }

    ret = iqr_ECDHCreatePrivateKey(params, rng, &alice_private_key);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_ECDHCreatePrivateKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = iqr_ECDHGetPublicKey(alice_private_key, alice_public_key, alice_public_key_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_ECDHGetPublicKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    if (dump) {
        ret = save_data(ALICE_KEY_FNAME, alice_public_key, alice_public_key_size);
        if (ret != IQR_OK) {
            goto end;
        }
    }

    ret = send_to_bob(alice_public_key, alice_public_key_size);

end:
    if (ret != IQR_OK) {
        iqr_ECDHDestroyPrivateKey(&alice_private_key);
    }
    free(alice_public_key);
    return ret;
}

iqr_retval alice_get_secret(uint8_t **secret, size_t *secret_size)
{
    iqr_retval ret = IQR_OK;
    uint8_t *bob_public_key = NULL;

    if (secret == NULL || secret_size == NULL) {
        fprintf(stderr, "The input parameters were bad.\n");
        ret = IQR_ENULLPTR;
        goto end;
    }

    size_t bob_public_key_size = 0;
    ret = iqr_ECDHGetPublicKeySize(params, &bob_public_key_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_ECDHGetPublicKeySize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    bob_public_key = calloc(1, bob_public_key_size);
    if (bob_public_key == NULL) {
        fprintf(stderr, "We seem to have run out of memory. ret=%d\n", errno);
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = receive_from_bob(bob_public_key, bob_public_key_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "We couldn't get the public key from Bob.\n");
        goto end;
    }

    size_t alice_secret_size = 0;
    ret = iqr_ECDHGetSecretSize(params, &alice_secret_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_ECDHGetSecretSize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    alice_secret = calloc(1, alice_secret_size);
    if (alice_secret == NULL) {
        fprintf(stderr, "We seem to have run out of memory. ret = %d\n", errno);
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_ECDHGetSecret(alice_private_key, bob_public_key, bob_public_key_size, alice_secret, alice_secret_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_ECDHGetSecret(): %s\n", iqr_StrError(ret));
        goto end;
    }

    *secret = alice_secret;
    *secret_size = alice_secret_size;

end:
    free(bob_public_key);
    iqr_ECDHDestroyPrivateKey(&alice_private_key);

    return ret;
}

iqr_retval cleanup_alice(void)
{
    free(alice_secret);
    alice_secret = NULL;

    iqr_retval ret = iqr_ECDHDestroyParams(&params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_ECDHDestroyParams(): %s\n", iqr_StrError(ret));
    }
    return ret;
}
