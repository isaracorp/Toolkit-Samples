/** @file main.c
 *
 * @brief Verify a signature using the toolkit's Dilithium signature scheme.
 *
 * @copyright Copyright (C) 2017-2020, ISARA Corporation
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
#include "iqr_dilithium.h"
#include "iqr_hash.h"
#include "iqr_retval.h"
#include "isara_samples.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Tell the user about the command-line arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"dilithium_verify [--variant 80|128|160] [--sig <filename>] [--pub <filename>]\n"
"  [--message <filename>]\n"
"\n"
"    Defaults:\n"
"        --variant 128\n"
"        --sig sig.dat\n"
"        --pub pub.key\n"
"        --message message.dat\n"
"\n"
"    The --variant must match the --variant specified when generating keys.\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the verification of a Dilithium signature against a
// digest.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_dilithium_verify(const iqr_Context *ctx, const iqr_DilithiumVariant *variant, const char *pub_file,
    const char *message_file, const char *sig_file)
{
    iqr_DilithiumParams *params = NULL;
    iqr_DilithiumPublicKey *pub = NULL;

    size_t pub_raw_size = 0;
    uint8_t *pub_raw = NULL;

    size_t message_size = 0;
    uint8_t *message = NULL;

    size_t sig_size = 0;
    uint8_t *sig = NULL;

    iqr_retval ret = iqr_DilithiumCreateParams(ctx, variant, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_DilithiumCreateParams(): %s\n", iqr_StrError(ret));
        goto end;
    }

    /* Load the public key, message and signature from disk. */
    ret = load_data(pub_file, &pub_raw, &pub_raw_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = load_data(message_file, &message, &message_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = load_data(sig_file, &sig, &sig_size);
    if (ret != IQR_OK) {
        goto end;
    }

    /* Import the public key data and create a public key object. */
    ret = iqr_DilithiumImportPublicKey(params, pub_raw, pub_raw_size, &pub);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_DilithiumImportPublicKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Public key has been loaded successfully!\n");

    ret = iqr_DilithiumVerify(pub, message, message_size, sig, sig_size);
    if (ret == IQR_OK) {
        fprintf(stdout, "Dilithium verified the signature successfully!\n");
    } else {
        fprintf(stderr, "Failed on iqr_DilithiumVerify(): %s\n", iqr_StrError(ret));
    }

    iqr_DilithiumDestroyPublicKey(&pub);

end:
    free(pub_raw);
    free(message);
    free(sig);

    iqr_DilithiumDestroyParams(&params);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// the Dilithium signature scheme.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval init_toolkit(iqr_Context **ctx)
{
    /* Create a Context. */
    iqr_retval ret = iqr_CreateContext(ctx);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_CreateContext(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This sets the hashing functions that will be used with this Context. */
    ret = iqr_HashRegisterCallbacks(*ctx, IQR_HASHALGO_SHA3_512, &IQR_HASH_DEFAULT_SHA3_512);
    if (IQR_OK != ret) {
        fprintf(stderr, "Failed on iqr_HashRegisterCallbacks(): %s\n", iqr_StrError(ret));
        return ret;
    }

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

static void preamble(const char *cmd, const iqr_DilithiumVariant *variant, const char *sig, const char *pub, const char *message)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    if (variant == &IQR_DILITHIUM_80) {
        fprintf(stdout, "    variant: IQR_DILITHIUM_80\n");
    } else if (variant == &IQR_DILITHIUM_128) {
        fprintf(stdout, "    variant: IQR_DILITHIUM_128\n");
    } else {
        fprintf(stdout, "    variant: IQR_DILITHIUM_160\n");
    }
    fprintf(stdout, "    signature file: %s\n", sig);
    fprintf(stdout, "    public key file: %s\n", pub);
    fprintf(stdout, "    message data file: %s\n", message);
    fprintf(stdout, "\n");
}

/* Parse the command line options. */
static iqr_retval parse_commandline(int argc, const char **argv, const iqr_DilithiumVariant **variant, const char **sig,
    const char **pub, const char **message)
{
    int i = 1;
    while (i != argc) {
        if (paramcmp(argv[i], "--variant") == 0) {
            /* [--variant 80|128|160] */
            i++;
            if (paramcmp(argv[i], "80") == 0) {
                *variant = &IQR_DILITHIUM_80;
            } else if (paramcmp(argv[i], "128") == 0) {
                *variant = &IQR_DILITHIUM_128;
            } else if (paramcmp(argv[i], "160") == 0) {
                *variant = &IQR_DILITHIUM_160;
            } else {
                fprintf(stdout, "%s", usage_msg);
                return IQR_EBADVALUE;
            }
        } else if (paramcmp(argv[i], "--sig") == 0) {
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
        } else {
            fprintf(stdout, "%s", usage_msg);
            return IQR_EBADVALUE;
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
    const iqr_DilithiumVariant *variant = &IQR_DILITHIUM_128;
    const char *sig = "sig.dat";
    const char *pub = "pub.key";
    const char *message = "message.dat";

    iqr_Context *ctx = NULL;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &variant, &sig, &pub, &message);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], variant, sig, pub, message);

    /* IQR initialization that is not specific to Dilithium. */
    ret = init_toolkit(&ctx);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase the verification of a Dilithium signature. */
    ret = showcase_dilithium_verify(ctx, variant, pub, message, sig);

cleanup:
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
