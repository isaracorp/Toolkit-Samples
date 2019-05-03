/** @file main.c
 *
 * @brief Sign a message using the toolkit's XMSS^MT signature scheme.
 *
 * @copyright Copyright (C) 2018-2019, ISARA Corporation
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
#include "iqr_retval.h"
#include "iqr_rng.h"
#include "iqr_xmssmt.h"
#include "isara_samples.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Document the command-line arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"xmssmt_sign [--sig filename] [--priv <filename>] [--state <filename>]\n"
"  [--variant 2e20_2d|2e20_4d|2e40_2d|2e40_4d|2e40_8d|2e60_3d|2e60_6d|2e60_12d]\n"
"  [--strategy cpu|memory|full] [--message <filename>]\n"
"    Defaults are: \n"
"        --sig sig.dat\n"
"        --priv priv.key\n"
"        --state priv.state\n"
"        --variant 2e20_4d\n"
"        --strategy full\n"
"        --message message.dat\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases signing of a digest using the XMSS^MT signature scheme.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_xmssmt_sign(const iqr_Context *ctx, const iqr_RNG *rng, const iqr_XMSSMTVariant *variant,
    const iqr_XMSSMTTreeStrategy *strategy, const uint8_t *digest, const char *priv_file, const char *state_file,
    const char *sig_file)
{
    iqr_XMSSMTParams *params = NULL;
    iqr_XMSSMTPrivateKey *priv = NULL;
    iqr_XMSSMTPrivateKeyState *state = NULL;

    size_t priv_raw_size = 0;
    uint8_t *priv_raw = NULL;

    size_t sig_size = 0;
    uint8_t *sig = NULL;

    size_t state_raw_size = 0;
    uint8_t *state_raw = NULL;

    uint64_t remaining_sigs = 0;

    iqr_retval ret = iqr_XMSSMTCreateParams(ctx, strategy, variant, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSMTCreateParams(): %s\n", iqr_StrError(ret));
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

    ret = iqr_XMSSMTImportPrivateKey(params, priv_raw, priv_raw_size, &priv);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSMTImportPrivateKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Private key has been imported.\n");

    ret = iqr_XMSSMTImportState(params, state_raw, state_raw_size, &state);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSMTImportState(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Private key state has been imported.\n");

    ret = iqr_XMSSMTGetSignatureCount(state, &remaining_sigs);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSMTGetSignatureCount(): %s\n", iqr_StrError(ret));
        goto end;
    }

    printf("Number of remaining signatures for this private key: %" PRIu64 ".\n", remaining_sigs);

    if (remaining_sigs == 0) {
        fprintf(stderr, "The private key cannot sign any more messages.\n");
        ret = IQR_ESTATEDEPLETED;
        goto end;
    }

    /* Determine the size of the resulting signature and allocate memory. */
    ret = iqr_XMSSMTGetSignatureSize(params, &sig_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSMTGetSignatureSize(): %s\n", iqr_StrError(ret));
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
     * Before signing, the value of state must be written to non-volatile
     * memory. Failure to do so could result in a SECURITY BREACH as it could
     * lead to the re-use of a one-time signature.
     *
     * This step has been omitted for brevity.
     *
     * For more information about this property of the XMSS^MT private key,
     * please refer to the XMSS^MT specification.
     *
     **************************************************************************/

    /* Create the signature. The signing API requires a minimum digest length of
     * 64 bytes. Hence, SHA2-512 was used to guarantee that length.
     */
    ret = iqr_XMSSMTSign(priv, rng, digest, IQR_SHA2_512_DIGEST_SIZE, state, sig, sig_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSMTSign(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Signature has been created.\n");

    /* IMPORTANT: Save the state to disk prior to saving the signature. This
     * mirrors the real world usage pattern where you must persist the state
     * prior to using the signature in order to avoid one-time-signature
     * reuse if something goes wrong.
     */
    ret = iqr_XMSSMTExportState(state, state_raw, state_raw_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSMTExportState(): %s\n", iqr_StrError(ret));
        goto end;
    }

    /* Save the updated state. */
    ret = save_data(state_file, state_raw, state_raw_size);
    if (ret != IQR_OK) {
        goto end;
    }

    /* And finally, write the signature to disk. */
    ret = save_data(sig_file, sig, sig_size);
    if (ret != IQR_OK) {
        goto end;
    }

    fprintf(stdout, "Signature and updated state have been saved to disk.\n");

    ret = iqr_XMSSMTGetSignatureCount(state, &remaining_sigs);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_XMSSMTGetSignatureCount(): %s\n", iqr_StrError(ret));
        goto end;
    }

    printf("Remaining signatures: %" PRIu64 ".\n", remaining_sigs);

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

    iqr_XMSSMTDestroyPrivateKey(&priv);
    iqr_XMSSMTDestroyState(&state);
    iqr_XMSSMTDestroyParams(&params);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// XMSS^MT.
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

static iqr_retval init_toolkit(iqr_Context **ctx, iqr_RNG **rng, const char *message, uint8_t **digest)
{
    uint8_t *message_raw = NULL;
    size_t message_raw_size = 0;

    /* Create a Global Context. */
    iqr_retval ret = iqr_CreateContext(ctx);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_CreateContext(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This sets the hashing functions that will be used globally. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_256, &IQR_HASH_DEFAULT_SHA2_256);
    if (IQR_OK != ret) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* SHA2-512 produces a 64-byte digest, which is required by iqr_XMSSMTSign.
     * Any 64-byte digest is suitable for signing.
     */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_512, &IQR_HASH_DEFAULT_SHA2_512);
    if (IQR_OK != ret) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This will let us give satisfactory randomness to the algorithm. */
    ret =  iqr_RNGCreateHMACDRBG(*ctx, IQR_HASHALGO_SHA2_256, rng);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RNGCreateHMACDRBG(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* The seed should be initialized from a guaranteed entropy source. This is
     * only an example; DO NOT INITIALIZE THE SEED LIKE THIS.
     */
    time_t seed = time(NULL);

    ret = iqr_RNGInitialize(*rng, (uint8_t *)&seed, sizeof(seed));
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_RNGInitialize(): %s\n", iqr_StrError(ret));
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

static void preamble(const char *cmd, const char *sig, const char *priv, const char *state,
    const iqr_XMSSMTVariant *variant, const iqr_XMSSMTTreeStrategy *strategy, const char *message)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    fprintf(stdout, "    signature file: %s\n", sig);
    fprintf(stdout, "    private key file: %s\n", priv);
    fprintf(stdout, "    private key state file: %s\n", state);

    if (&IQR_XMSSMT_2E20_2D == variant) {
        fprintf(stdout, "    variant: IQR_XMSSMT_2E20_2D\n");
    } else if (&IQR_XMSSMT_2E20_4D == variant) {
        fprintf(stdout, "    variant: IQR_XMSSMT_2E20_4D\n");
    } else if (&IQR_XMSSMT_2E40_2D == variant) {
        fprintf(stdout, "    variant: IQR_XMSSMT_2E40_2D\n");
    } else if (&IQR_XMSSMT_2E40_4D == variant) {
        fprintf(stdout, "    variant: IQR_XMSSMT_2E40_4D\n");
    } else if (&IQR_XMSSMT_2E40_8D == variant) {
        fprintf(stdout, "    variant: IQR_XMSSMT_2E40_8D\n");
    } else if (&IQR_XMSSMT_2E60_3D == variant) {
        fprintf(stdout, "    variant: IQR_XMSSMT_2E60_3D\n");
    } else if (&IQR_XMSSMT_2E60_6D == variant) {
        fprintf(stdout, "    variant: IQR_XMSSMT_2E60_6D\n");
    } else if (&IQR_XMSSMT_2E60_12D == variant) {
        fprintf(stdout, "    variant: IQR_XMSSMT_2E60_12D\n");
    } else {
        fprintf(stdout, "    variant: INVALID\n");
    }

    if (strategy == &IQR_XMSSMT_FULL_TREE_STRATEGY) {
        fprintf(stdout, "    strategy: Full Tree\n");
    } else if (strategy == &IQR_XMSSMT_MEMORY_CONSTRAINED_STRATEGY) {
        fprintf(stdout, "    strategy: Memory Constrained\n");
    } else if (strategy == &IQR_XMSSMT_CPU_CONSTRAINED_STRATEGY) {
        fprintf(stdout, "    strategy: CPU Constrained\n");
    } else {
        fprintf(stdout, "    strategy: INVALID\n");
    }

    fprintf(stdout, "    message data file: %s\n", message);
    fprintf(stdout, "\n");
}

static iqr_retval parse_commandline(int argc, const char **argv, const char **sig, const char **priv, const char **state,
    const iqr_XMSSMTVariant **variant, const iqr_XMSSMTTreeStrategy **strategy, const char **message)
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
            /* [--variant 2e20_2d|2e20_4d|2e40_2d|2e40_4d|2e40_8d|2e60_3d|2e60_6d|2e60_12d] */
            i++;
            if  (paramcmp(argv[i], "2e20_2d") == 0) {
                *variant = &IQR_XMSSMT_2E20_2D;
            } else if  (paramcmp(argv[i], "2e20_4d") == 0) {
                *variant = &IQR_XMSSMT_2E20_4D;
            } else if  (paramcmp(argv[i], "2e40_2d") == 0) {
                *variant = &IQR_XMSSMT_2E40_2D;
            } else if  (paramcmp(argv[i], "2e40_4d") == 0) {
                *variant = &IQR_XMSSMT_2E40_4D;
            } else if  (paramcmp(argv[i], "2e40_8d") == 0) {
                *variant = &IQR_XMSSMT_2E40_8D;
            } else if  (paramcmp(argv[i], "2e60_3d") == 0) {
                *variant = &IQR_XMSSMT_2E60_3D;
            } else if  (paramcmp(argv[i], "2e60_6d") == 0) {
                *variant = &IQR_XMSSMT_2E60_6D;
            } else if  (paramcmp(argv[i], "2e60_12d") == 0) {
                *variant = &IQR_XMSSMT_2E60_12D;
            } else {
                fprintf(stdout, "%s", usage_msg);
                return IQR_EBADVALUE;
            }
        } else if (paramcmp(argv[i], "--message") == 0) {
           /* [--message <filename>] */
           i++;
           *message = argv[i];
        } else if (paramcmp(argv[i], "--strategy") == 0) {
            /* [--strategy cpu|memory|full] */
            i++;

            if (paramcmp(argv[i], "cpu") == 0) {
                *strategy = &IQR_XMSSMT_CPU_CONSTRAINED_STRATEGY;
            } else if (paramcmp(argv[i], "memory") == 0) {
                *strategy = &IQR_XMSSMT_MEMORY_CONSTRAINED_STRATEGY;
            } else if (paramcmp(argv[i], "full") == 0) {
                *strategy = &IQR_XMSSMT_FULL_TREE_STRATEGY;
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
    /* Default values.  Please adjust the usage message if you make changes
     *  here.
     */
    const char *sig = "sig.dat";
    const char *priv = "priv.key";
    const char *state = "priv.state";
    const char *message = "message.dat";
    const iqr_XMSSMTTreeStrategy *strategy = &IQR_XMSSMT_FULL_TREE_STRATEGY;
    const iqr_XMSSMTVariant *variant = &IQR_XMSSMT_2E20_4D;

    iqr_Context *ctx = NULL;
    iqr_RNG *rng = NULL;
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

    /* IQR initialization that is not specific to XMSS^MT. */
    ret = init_toolkit(&ctx, &rng, message, &digest);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* This function showcases the usage of XMSS^MT signing.
     */
    ret = showcase_xmssmt_sign(ctx, rng, variant, strategy, digest, priv, state, sig);

cleanup:
    iqr_RNGDestroy(&rng);
    iqr_DestroyContext(&ctx);
    free(digest);

    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
