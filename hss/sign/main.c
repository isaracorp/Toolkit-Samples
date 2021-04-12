/** @file main.c
 *
 * @brief Sign a message using the toolkit's HSS signature scheme.
 *
 * @copyright Copyright (C) 2016-2021, ISARA Corporation, All Rights Reserved.
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

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "iqr_context.h"
#include "iqr_hash.h"
#include "iqr_hss.h"
#include "iqr_retval.h"
#include "iqr_rng.h"
#include "isara_samples.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Document the command-line arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"hss_sign [--sig <filename>] [--priv <filename>] [--state <filename>]\n"
"  [--variant 2e15f|2e15s]\n"
"  [--strategy memory|full]\n"
"  [--message <filename>]\n"
"\n"
"    The 'f' variants is Fast, the 's' variants is Small.\n"
"\n"
"    Defaults:\n"
"        --sig sig.dat\n"
"        --priv priv.key\n"
"        --state priv.state\n"
"        --strategy full\n"
"        --variant 2e15f\n"
"        --message message.dat\n"
"\n"
"    The --strategy and --variant must match the --strategy and --variant\n"
"    specified when generating keys.\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases signing a digest using the HSS signature scheme.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_hss_sign(const iqr_Context *ctx, const iqr_HSSVariant *variant, const iqr_HSSTreeStrategy *strategy,
    const uint8_t *digest, const char *priv_file, const char *state_file, const char *sig_file)
{
    iqr_HSSParams *params = NULL;
    iqr_HSSPrivateKey *priv = NULL;
    iqr_HSSPrivateKeyState *state = NULL;

    size_t priv_raw_size = 0;
    uint8_t *priv_raw = NULL;

    size_t sig_size = 0;
    uint8_t *sig = NULL;

    size_t state_raw_size = 0;
    uint8_t *state_raw = NULL;

    uint32_t remaining_sigs = 0;

    iqr_retval ret = iqr_HSSCreateParams(ctx, strategy, variant, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HSSCreateParams(): %s\n", iqr_StrError(ret));
        goto end;
    }

    /* Load the raw private key. */
    ret = load_data(priv_file, &priv_raw, &priv_raw_size);
    if (ret != IQR_OK) {
        goto end;
    }

    /* Load the private key state. */
    ret = load_data(state_file, &state_raw, &state_raw_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = iqr_HSSImportPrivateKey(params, priv_raw, priv_raw_size, &priv);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HSSImportPrivateKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Private key has been imported.\n");

    ret = iqr_HSSImportState(params, state_raw, state_raw_size, &state);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HSSImportState(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Private key state has been imported.\n");

    /* Determine the size of the resulting signature and allocate memory. */
    ret = iqr_HSSGetSignatureSize(params, &sig_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HSSGetSignatureSize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    sig = calloc(1, sig_size);
    if (sig == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    /*********************** CRITICALLY IMPORTANT STEP *************************
     *
     * You must detach a state to use for signing, and write the remaining state
     * to non-volatile memory, before signing. Failure to do so could result in
     * a security breach as it could lead to the re-use of a one-time signature.
     *
     * This step has been omitted for brevity.
     *
     * For more information about this property of the HSS state, please refer
     * to the HSS specification.
     *
     **************************************************************************/

    ret = iqr_HSSSign(priv, digest, IQR_SHA2_512_DIGEST_SIZE, state, sig, sig_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HSSSign(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Signature has been created.\n");

    /* IMPORTANT: Save the state to disk prior to saving the signature. This
     * mirrors the real world usage pattern where you must persist the state
     * prior to using the signature to avoid reusing one-time signatures
     * if something goes wrong.
     *
     * If saving the state does fail for any reason, you must wipe the
     * signature buffer and NOT return a signature. Even if the signature in
     * the buffer is valid, the next signature will be a security breach.
     */
    size_t export_state_size = 0;
    ret = iqr_HSSGetStateSize(params, &export_state_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HSSGetStateSize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = iqr_HSSExportState(state, state_raw, export_state_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HSSExportState(): %s\n", iqr_StrError(ret));
        goto end;
    }

    /* Save the updated state. */
    ret = save_data(state_file, state_raw, export_state_size);
    if (ret != IQR_OK) {
        goto end;
    }

    /* And finally, write the signature to disk. */
    ret = save_data(sig_file, sig, sig_size);
    if (ret != IQR_OK) {
        goto end;
    }

    fprintf(stdout, "Signature and updated state have been saved to disk.\n");

    ret = iqr_HSSGetSignatureCount(state, &remaining_sigs);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HSSGetMaximumSignatureCount(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Remaining signatures: %u.\n", remaining_sigs);

    if (remaining_sigs == 0) {
        fprintf(stderr, "The private key cannot sign any more messages.\n");
    }

end:
    if (priv_raw != NULL) {
        /* (Private) Keys are private, sensitive data, be sure to clear memory
         * containing them when you're done.
         */
        secure_memzero(priv_raw, priv_raw_size);
    }
    free(sig);
    free(priv_raw);
    free(state_raw);

    iqr_HSSDestroyPrivateKey(&priv);
    iqr_HSSDestroyState(&state);
    iqr_HSSDestroyParams(&params);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// The next section is related to the toolkit, but is not specific to HSS.
// ---------------------------------------------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------------------------------------------
// This function takes a message buffer and creates a digest out of it.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval create_digest(const iqr_Context *ctx, uint8_t *data, size_t data_size, uint8_t *out_digest)
{
    iqr_Hash *hash = NULL;
    iqr_retval ret = iqr_HashCreate(ctx, IQR_HASHALGO_SHA2_512, &hash);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashCreate(): %s\n", iqr_StrError(ret));
        return ret;
    }

    ret = iqr_HashMessage(hash, data, data_size, out_digest, IQR_SHA2_512_DIGEST_SIZE);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashMessage(): %s\n", iqr_StrError(ret));
        iqr_HashDestroy(&hash);
        return ret;
    }

    iqr_HashDestroy(&hash);
    return IQR_OK;
}

static iqr_retval init_toolkit(iqr_Context **ctx, const char *message, uint8_t **digest)
{
    uint8_t *message_raw = NULL;
    size_t message_raw_size = 0;

    /* Create a Context. */
    iqr_retval ret = iqr_CreateContext(ctx);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_CreateContext(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This sets the hashing functions that will be used with this Context. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_256, &IQR_HASH_DEFAULT_SHA2_256);
    if (IQR_OK != ret) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* SHA2-512 produces a 64-byte digest. Any 64-byte digest is suitable for
     * signing.
     */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_512, &IQR_HASH_DEFAULT_SHA2_512);
    if (IQR_OK != ret) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* Before we do any more work, lets make sure we can load the message
     * file.
     */
    ret = load_data(message, &message_raw, &message_raw_size);
    if (ret != IQR_OK) {
        return ret;
    }
    if (message_raw_size < 1) {
        fprintf(stderr, "Input message must be one or more bytes long.\n");
        return IQR_EINVBUFSIZE;
    }

    *digest = calloc(1, IQR_SHA2_512_DIGEST_SIZE);
    if (NULL == *digest) {
        fprintf(stderr, "Failed to allocate space for the digest\n");
        free(message_raw);
        return IQR_ENOMEM;
    }

    /* Calculate the digest */
    ret = create_digest(*ctx, message_raw, message_raw_size, *digest);
    if (ret != IQR_OK) {
        free(message_raw);
        free(*digest);
        *digest = NULL;
        return ret;
    }

    free(message_raw);
    return IQR_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// These functions are designed to help the end user understand how to use
// this sample and hold little value to the developer trying to learn how to
// use the toolkit.
// ---------------------------------------------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------------------------------------------
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, const char *sig, const char *priv, const char *state, const iqr_HSSVariant *variant,
    const iqr_HSSTreeStrategy *strategy, const char *message)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    fprintf(stdout, "    signature file: %s\n", sig);
    fprintf(stdout, "    private key file: %s\n", priv);
    fprintf(stdout, "    private key state file: %s\n", state);

    if (variant == &IQR_HSS_2E15_FAST) {
        fprintf(stdout, "    Variant: IQR_HSS_2E15_FAST\n");
    } else if (variant == &IQR_HSS_2E15_SMALL) {
        fprintf(stdout, "    Variant: IQR_HSS_2E15_SMALL\n");
    } else {
        fprintf(stdout, "    Variant: INVALID\n");
    }

    if (strategy == &IQR_HSS_FULL_TREE_STRATEGY) {
        fprintf(stdout, "    strategy: Full Tree\n");
    } else if (strategy == &IQR_HSS_MEMORY_CONSTRAINED_STRATEGY) {
        fprintf(stdout, "    strategy: Memory Constrained\n");
    } else {
        fprintf(stdout, "    strategy: INVALID\n");
    }

    fprintf(stdout, "    message data file: %s\n", message);
    fprintf(stdout, "\n");
}

static iqr_retval parse_commandline(int argc, const char **argv, const char **sig, const char **priv, const char **state,
    const iqr_HSSVariant **variant, const iqr_HSSTreeStrategy **strategy, const char **message)
{
    int i = 1;
    while (i != argc) {
        if (i + 2 > argc) {
            fprintf(stdout, "%s", usage_msg);
            return IQR_EBADVALUE;
        }

        if (paramcmp(argv[i], "--sig") == 0) {
            /* [--sig <filename>] */
            i++;
            *sig = argv[i];
        } else if (paramcmp(argv[i], "--priv") == 0) {
            /* [--priv <filename>] */
            i++;
            *priv = argv[i];
        } else if (paramcmp(argv[i], "--state") == 0) {
            /* [--state <filename>] */
            i++;
            *state = argv[i];
        } else if (paramcmp(argv[i], "--variant") == 0) {
            i++;
            if (paramcmp(argv[i], "2e15f") == 0) {
                *variant = &IQR_HSS_2E15_FAST;
            } else if (paramcmp(argv[i], "2e15s") == 0) {
                *variant = &IQR_HSS_2E15_SMALL;
            } else {
                fprintf(stdout, "%s", usage_msg);
                return IQR_EBADVALUE;
            }
        } else if (paramcmp(argv[i], "--message") == 0) {
            /* [--message <filename>] */
            i++;
            *message = argv[i];
        } else if (paramcmp(argv[i], "--strategy") == 0) {
            /* [--strategy memory|full] */
            i++;
            if (paramcmp(argv[i], "memory") == 0) {
                *strategy = &IQR_HSS_MEMORY_CONSTRAINED_STRATEGY;
            } else if (paramcmp(argv[i], "full") == 0) {
                *strategy = &IQR_HSS_FULL_TREE_STRATEGY;
            } else {
                fprintf(stdout, "%s", usage_msg);
                return IQR_EBADVALUE;
            }
        }
        i++;
    }

    return IQR_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Executable entry point.
// ---------------------------------------------------------------------------------------------------------------------------------

int main(int argc, const char **argv)
{
    /* Default values. Please adjust the usage message if you make changes here.
     */
    const char *sig = "sig.dat";
    const char *priv = "priv.key";
    const char *state = "priv.state";
    const char *message = "message.dat";
    const iqr_HSSTreeStrategy *strategy = &IQR_HSS_FULL_TREE_STRATEGY;
    const iqr_HSSVariant *variant = &IQR_HSS_2E15_FAST;

    iqr_Context *ctx = NULL;
    uint8_t *digest = NULL;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &sig, &priv, &state, &variant, &strategy, &message);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], sig, priv, state, variant, strategy, message);

    /* IQR initialization that is not specific to HSS. */
    ret = init_toolkit(&ctx, message, &digest);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* This function showcases HSS signing. */
    ret = showcase_hss_sign(ctx, variant, strategy, digest, priv, state, sig);

cleanup:
    iqr_DestroyContext(&ctx);
    free(digest);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
