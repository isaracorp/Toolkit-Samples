/** @file main.c
 *
 * @brief Sign a message using the toolkit's Dilithium signature scheme.
 *
 * @copyright Copyright (C) 2018-2021, ISARA Corporation, All Rights Reserved.
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
#include <time.h>

#include "iqr_context.h"
#include "iqr_dilithium.h"
#include "iqr_hash.h"
#include "iqr_retval.h"
#include "iqr_rng.h"
#include "isara_samples.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Document the command-line arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"dilithium_sign [--variant 2|3|5] [--sig filename] [--priv <filename>]\n"
"  [--message <filename>]\n"
"\n"
"    Defaults:\n"
"        --variant 3\n"
"        --sig sig.dat\n"
"        --priv priv.key\n"
"        --message message.dat\n"
"\n"
"    The --variant must match the --variant specified when generating keys.\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases signing of a digest using the Dilithium signature
// scheme.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_dilithium_sign(const iqr_Context *ctx, const iqr_DilithiumVariant *variant, const char *priv_file,
    const char *message_file, const char *sig_file)
{
    iqr_DilithiumParams *params = NULL;
    iqr_DilithiumPrivateKey *priv = NULL;

    size_t priv_raw_size = 0;
    uint8_t *priv_raw = NULL;

    size_t message_size = 0;
    uint8_t *message = NULL;

    size_t sig_size = 0;
    uint8_t *sig = NULL;

    iqr_retval ret = iqr_DilithiumCreateParams(ctx, variant, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_DilithiumCreateParams(): %s\n", iqr_StrError(ret));
        goto end;
    }

    /* Load the raw private key. */
    ret = load_data(priv_file, &priv_raw, &priv_raw_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = iqr_DilithiumImportPrivateKey(params, priv_raw, priv_raw_size, &priv);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_DilithiumImportPrivateKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Private key has been imported.\n");

    /* Load the message. */
    ret = load_data(message_file, &message, &message_size);
    if (ret != IQR_OK) {
        goto end;
    }

    /* Create the signature. */
    ret = iqr_DilithiumGetSignatureSize(params, &sig_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_DilithiumGetSignatureSize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    sig = calloc(1, sig_size);
    if (sig == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    ret = iqr_DilithiumSign(priv, message, message_size, sig, sig_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_DilithiumSign(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Signature has been created.\n");

    /* And finally, write the signature to disk. */
    ret = save_data(sig_file, sig, sig_size);
    if (ret != IQR_OK) {
        goto end;
    }

    fprintf(stdout, "Signature has been saved to disk.\n");

end:
    if (priv_raw != NULL) {
        /* (Private) Keys are private, sensitive data, be sure to clear memory
         * containing them when you're done.
         */
        secure_memzero(priv_raw, priv_raw_size);
    }

    iqr_DilithiumDestroyPrivateKey(&priv);
    iqr_DilithiumDestroyParams(&params);

    free(priv_raw);
    free(message);
    free(sig);

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

static void preamble(const char *cmd, const iqr_DilithiumVariant *variant, const char *sig, const char *priv, const char *message)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    if (variant == &IQR_DILITHIUM_2) {
        fprintf(stdout, "    variant: IQR_DILITHIUM_2\n");
    } else if (variant == &IQR_DILITHIUM_3) {
        fprintf(stdout, "    variant: IQR_DILITHIUM_3\n");
    } else {
        fprintf(stdout, "    variant: IQR_DILITHIUM_5\n");
    }
    fprintf(stdout, "    signature file: %s\n", sig);
    fprintf(stdout, "    private key file: %s\n", priv);
    fprintf(stdout, "    message data file: %s\n", message);
    fprintf(stdout, "\n");
}

/* Parse the command line options. */
static iqr_retval parse_commandline(int argc, const char **argv, const iqr_DilithiumVariant **variant, const char **sig,
    const char **priv, const char **message)
{
    int i = 1;
    while (i != argc) {
        if (paramcmp(argv[i], "--variant") == 0) {
            /* [--variant 2|3|5] */
            i++;
            if (paramcmp(argv[i], "2") == 0) {
                *variant = &IQR_DILITHIUM_2;
            } else if (paramcmp(argv[i], "3") == 0) {
                *variant = &IQR_DILITHIUM_3;
            } else if (paramcmp(argv[i], "5") == 0) {
                *variant = &IQR_DILITHIUM_5;
            } else {
                fprintf(stdout, "%s", usage_msg);
                return IQR_EBADVALUE;
            }
        } else if (paramcmp(argv[i], "--sig") == 0) {
            /* [--sig <filename>] */
            i++;
            *sig = argv[i];
        } else if (paramcmp(argv[i], "--priv") == 0) {
            /* [--priv <filename>] */
            i++;
            *priv = argv[i];
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
    const iqr_DilithiumVariant *variant = &IQR_DILITHIUM_3;
    const char *sig = "sig.dat";
    const char *priv = "priv.key";
    const char *message = "message.dat";

    iqr_Context *ctx = NULL;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &variant, &sig, &priv, &message);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], variant, sig, priv, message);

    /* IQR initialization that is not specific to Dilithium. */
    ret = init_toolkit(&ctx);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase the generation of a Dilithium signature. */
    ret = showcase_dilithium_sign(ctx, variant, priv, message, sig);

cleanup:
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
