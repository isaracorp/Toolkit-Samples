/** @file main.c
 *
 * @brief Get parameters from a signature, then verify using the toolkit's HSS
 * signature scheme.
 *
 * @copyright Copyright (C) 2019-2023, ISARA Corporation, All Rights Reserved.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iqr_context.h"
#include "iqr_hash.h"
#include "iqr_hss.h"
#include "iqr_retval.h"
#include "isara_samples.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Document the command-line arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"hss_verify_from_sig [--sig <filename>] [--pub <filename>]\n"
"  [--message <filename>]\n"
"\n"
"    Defaults:\n"
"        --sig sig.dat\n"
"        --pub pub.key\n"
"        --message message.dat\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the verification of an HSS signature against a
// digest after retrieving the HSS parameters from the signature.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_hss_verify_from_sig(const iqr_Context *ctx, const uint8_t *digest, const char *pub_file,
    const char *sig_file)
{
    iqr_HSSParams *params = NULL;
    iqr_HSSPublicKey *pub = NULL;

    size_t pub_raw_size = 0;
    uint8_t *pub_raw = NULL;

    size_t sig_size = 0;
    uint8_t *sig = NULL;

    /* Load the signature from disk. */
    iqr_retval ret = load_data(sig_file, &sig, &sig_size);
    if (ret != IQR_OK) {
        goto end;
    }

    /* This will automatically choose the VERIFY ONLY strategy. */
    ret = iqr_HSSCreateParamsFromSignature(ctx, sig, sig_size, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HSSCreateParamsFromSignature(): %s\n", iqr_StrError(ret));
        goto end;
    }

    /* Load the public key from disk. */
    ret = load_data(pub_file, &pub_raw, &pub_raw_size);
    if (ret != IQR_OK) {
        goto end;
    }

    /* Import the public key data and create a public key object. */
    ret = iqr_HSSImportPublicKey(params, pub_raw, pub_raw_size, &pub);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HSSImportPublicKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Public key has been loaded successfully!\n");

    ret = iqr_HSSVerify(pub, digest, IQR_SHA2_512_DIGEST_SIZE, sig, sig_size);
    if (ret == IQR_OK) {
        fprintf(stdout, "HSS verified the signature successfully!\n");
    } else {
        fprintf(stderr, "Failed on iqr_HSSVerify(): %s\n", iqr_StrError(ret));
    }

    iqr_HSSDestroyPublicKey(&pub);

end:
    free(pub_raw);
    free(sig);

    iqr_HSSDestroyParams(&params);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// HSS.
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

    /* The HSS scheme will sign a digest of the message, so we need a digest
     * of our message. This will give us that digest.
     */
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

    /* SHA2-512 is used on the message before signing in the hss_sign sample. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA2_512, &IQR_HASH_DEFAULT_SHA2_512);
    if (IQR_OK != ret) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* Before we do any work, lets make sure we can load the message file. */
    ret = load_data(message, &message_raw, &message_raw_size);
    if (ret != IQR_OK) {
        return ret;
    }

    *digest = calloc(1, IQR_SHA2_512_DIGEST_SIZE);
    if (*digest == NULL) {
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

static void preamble(const char *cmd, const char *sig, const char *pub, const char *message)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    fprintf(stdout, "    signature file: %s\n", sig);
    fprintf(stdout, "    public key file: %s\n", pub);
    fprintf(stdout, "    message data file: %s\n", message);
    fprintf(stdout, "\n");
}

static iqr_retval parse_commandline(int argc, const char **argv, const char **sig, const char **pub, const char **message)
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
        } else if (paramcmp(argv[i], "--pub") == 0) {
            /* [--pub <filename>] */
            i++;
            *pub = argv[i];
        } else if (paramcmp(argv[i], "--message") == 0) {
            /* [--message <filename>] */
            i++;
            *message = argv[i];
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
    /* Default values. Please adjust the usage message if you make changes
     * here.
     */
    const char *sig = "sig.dat";
    const char *pub = "pub.key";
    const char *message = "message.dat";

    iqr_Context *ctx = NULL;
    uint8_t *digest = NULL;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &sig, &pub, &message);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], sig, pub, message);

    /* IQR initialization that is not specific to HSS. */
    ret = init_toolkit(&ctx, message, &digest);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* This function showcases the usage of HSS signature verification. */
    ret = showcase_hss_verify_from_sig(ctx, digest, pub, sig);

cleanup:
    iqr_DestroyContext(&ctx);
    free(digest);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
