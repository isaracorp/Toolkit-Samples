/** @file main.c Sign a message using the Toolkit's LMS signature scheme.
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "iqr_context.h"
#include "iqr_hash.h"
#include "iqr_lms.h"
#include "iqr_retval.h"
#include "iqr_rng.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Function Declarations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval save_data(const char *fname, const uint8_t *data, size_t data_size);
static iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size);
static void *secure_memset(void *b, int c, size_t len);

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases signing of a digest using the LMS signature scheme.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_lms_sign(const iqr_Context *ctx, const iqr_RNG *rng, const uint8_t *security,
    const size_t security_size, const iqr_LMSWinternitz w, const iqr_LMSHeight height, const uint8_t *digest, const char *priv_file,
    uint32_t q, const char *sig_file)
{
    iqr_LMSParams *params = NULL;
    iqr_LMSPrivateKey *priv = NULL;

    size_t priv_raw_size = 0;
    uint8_t *priv_raw = NULL;

    size_t sig_size = 0;
    uint8_t *sig = NULL;

    uint32_t remaining = 0;
    uint32_t max_sigs = 0;

    iqr_retval ret = iqr_LMSCreateParams(ctx, w, height, security, security_size, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_LMSCreateParams(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = iqr_LMSGetMaximumSignatureCount(params, &max_sigs);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_LMSGetMaximumSignatureCount(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Number of signatures for this private key: %d.\n", max_sigs);

    if (q > max_sigs) {
        fprintf(stderr, "The private key cannot sign any more messages. q = %d.\n", q);
        ret = IQR_EKEYDEPLETED;
        goto end;
    }

    /* Load the raw private key. */
    ret = load_data(priv_file, &priv_raw, &priv_raw_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = iqr_LMSImportPrivateKey(params, priv_raw, priv_raw_size, &priv);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_LMSImportPrivateKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Private key has been imported.\n");

    /* Determine the size of the resulting signature and allocate memory. */
    ret = iqr_LMSGetSignatureSize(params, &sig_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_LMSGetSignatureSize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    sig = calloc(1, sig_size);
    if (sig == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    /************************* CRITICALLY IMPORTANT STEP *************************
     *
     * Before signing, the value of q+1 must be written to non-volatile memory.
     * Failure to do so could result in a SECURITY BREACH as it could lead to the
     * re-use of a one-time signature.
     *
     * This step has been omitted for brevity. Next time you sign, use q+1.
     *
     * For more information about this property of the LMS private key, please
     * refer to the LMS specification.
     *
     *****************************************************************************/

    /* Create the signature. */
    ret = iqr_LMSSign(priv, rng, q, digest, IQR_SHA2_256_DIGEST_SIZE, sig, sig_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_LMSSign(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Signature has been created.\n");

    ret = iqr_LMSGetRemainingSignatureCount(params, q + 1, &remaining);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_LMSGetRemainingSignatureCount(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "The private key can sign %d more messages.\n", remaining);
    fprintf(stdout, "IMPORTANT: Next time you sign, use q+1 (%d).\n", q + 1);

    /* And finally, write the signature to disk. */
    ret = save_data(sig_file, sig, sig_size);
    if (ret != IQR_OK) {
        goto end;
    }

    fprintf(stdout, "Signature has been saved to disk.\n");

end:
    if (priv_raw != NULL) {
        /* (Private) Keys are private, sensitive data, be sure to clear memory containing them when you're done */
        secure_memset(priv_raw, 0, priv_raw_size);
    }
    free(sig);
    free(priv_raw);

    iqr_LMSDestroyPrivateKey(&priv);
    iqr_LMSDestroyParams(&params);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// LMS.
// ---------------------------------------------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------------------------------------------
// This function takes a message buffer and creates a digest out of it.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval create_digest(const iqr_Context *ctx, uint8_t *data, size_t data_size, uint8_t *out_digest)
{
    iqr_Hash *hash = NULL;
    iqr_retval ret = iqr_HashCreate(ctx, IQR_HASHALGO_SHA2_256, &hash);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HashCreate(): %s\n", iqr_StrError(ret));
        return ret;
    }

    ret = iqr_HashMessage(hash, data, data_size, out_digest, IQR_SHA2_256_DIGEST_SIZE);
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

    /* This will allow us to give satisfactory randomness to the algorithm. */
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

    *digest = calloc(1, IQR_SHA2_256_DIGEST_SIZE);
    if (NULL == *digest) {
        fprintf(stderr, "Failed to allocate space for the digest\n");
        free(message_raw);
        return IQR_ENOMEM;
    }

    /* calculate the digest */
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
// Generic Posix file stream I/O operations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval save_data(const char *fname, const uint8_t *data, size_t data_size)
{
    FILE *fp = fopen(fname, "w");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", fname, strerror(errno));
        return IQR_EBADVALUE;
    }

    iqr_retval ret = IQR_OK;
    fwrite(data, data_size, 1, fp);
    if (ferror(fp) != 0) {
        fprintf(stderr, "Failed on fwrite(): %s\n", strerror(errno));
        ret = IQR_EBADVALUE;
        goto end;
    }

    fprintf(stdout, "Successfully saved %s (%zu bytes)\n", fname, data_size);

end:
    fclose(fp);
    fp = NULL;
    return ret;
}

static iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size)
{
    FILE *fp = fopen(fname, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", fname, strerror(errno));
        return IQR_EBADVALUE;
    }

    /* Obtain file size. */
    fseek(fp , 0 , SEEK_END);
    size_t tmp_size = (size_t)ftell(fp);
    rewind(fp);

    iqr_retval ret = IQR_OK;
    uint8_t *tmp = NULL;
    if (tmp_size != 0) {
        /* calloc with a param of 0 could return a pointer or NULL depending on implementation,
         * so skip all this when the size is 0 so we consistently return NULL with a size of 0.
         * In some samples it's useful to take empty files as input so users can pass NULL or 0
         * for optional parameters.
         */
        tmp = calloc(1, tmp_size);
        if (tmp == NULL) {
            fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
            ret = IQR_EBADVALUE;
            goto end;
        }

        size_t read_size = fread(tmp, 1, tmp_size, fp);
        if (read_size != tmp_size) {
            fprintf(stderr, "Failed on fread(): %s\n", strerror(errno));
            free(tmp);
            tmp = NULL;
            ret = IQR_EBADVALUE;
            goto end;
        }
    }

    *data_size = tmp_size;
    *data = tmp;

    fprintf(stdout, "Successfully loaded %s (%zu bytes)\n", fname, *data_size);

end:
    fclose(fp);
    fp = NULL;
    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Tell the user about the command-line arguments.
// ---------------------------------------------------------------------------------------------------------------------------------

static void usage(void)
{
    fprintf(stdout, "lms_sign --q <number> [--security <identifier>] \n"
        "  [--sig filename] [--priv <filename>]\n"
        "  [--winternitz 1|2|4|8] [--height 5|10|20]\n"
        "  [--message <filename>]\n");
    fprintf(stdout, "    Defaults are: \n");
    fprintf(stdout, "        --security \"** ISARA LMS KEY IDENTIFIER ***\" (must be 31 bytes)\n");
    fprintf(stdout, "        --sig sig.dat\n");
    fprintf(stdout, "        --priv priv.key\n");
    fprintf(stdout, "        --winternitz 4\n");
    fprintf(stdout, "        --height 5\n");
    fprintf(stdout, "        --message message.dat\n");
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, const char *security, const char *sig, const char *priv, const iqr_LMSWinternitz w,
    const iqr_LMSHeight height, uint32_t q, const char *message)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    fprintf(stdout, "    security string: %s\n", security);
    fprintf(stdout, "    signature file: %s\n", sig);
    fprintf(stdout, "    private key file: %s\n", priv);

    if (IQR_LMS_WINTERNITZ_1 == w) {
        fprintf(stdout, "    winternitz value: IQR_LMS_WINTERNITZ_1\n");
    } else if (IQR_LMS_WINTERNITZ_2 == w) {
        fprintf(stdout, "    winternitz value: IQR_LMS_WINTERNITZ_2\n");
    } else if (IQR_LMS_WINTERNITZ_4 == w) {
        fprintf(stdout, "    winternitz value: IQR_LMS_WINTERNITZ_4\n");
    } else if (IQR_LMS_WINTERNITZ_8 == w) {
        fprintf(stdout, "    winternitz value: IQR_LMS_WINTERNITZ_8\n");
    } else {
        fprintf(stdout, "    winternitz value: INVALID\n");
    }

    if (IQR_LMS_HEIGHT_5 == height) {
        fprintf(stdout, "    height: IQR_LMS_HEIGHT_5\n");
    } else if (IQR_LMS_HEIGHT_10 == height) {
        fprintf(stdout, "    height: IQR_LMS_HEIGHT_10\n");
    } else if (IQR_LMS_HEIGHT_20 == height) {
        fprintf(stdout, "    height: IQR_LMS_HEIGHT_20\n");
    } else {
        fprintf(stdout, "    height: INVALID\n");
    }
    fprintf(stdout, "    q: %d\n", q);
    fprintf(stdout, "    message data file: %s\n", message);
    fprintf(stdout, "\n");
}

/* Tests if two parameters match.
 * Returns 0 if the two parameter match.
 * Non-zero otherwise.
 *
 * Parameters are expected to be less than 32 characters in length
 */
static int paramcmp(const char *p1 , const char *p2) {
    const size_t max_param_size = 32; //arbitrary, but reasonable.
    if (strnlen(p1, max_param_size) != strnlen(p2, max_param_size)) {
        return 1;
    }
    return strncmp(p1, p2, max_param_size);
}

static iqr_retval parse_commandline(int argc, const char **argv,  const char **security, const char **sig, const char **priv,
    uint32_t *q, iqr_LMSWinternitz *w, iqr_LMSHeight *height, const char **message)
{
    // Set to an improbable value so we can check if it was provided by user.
    *q = UINT32_MAX;

    int i = 1;
    while (i != argc) {
        if (i + 2 > argc) {
            usage();
            return IQR_EBADVALUE;
        }

        if (paramcmp(argv[i], "--security") == 0) {
            /* [--security <identifier>] */
            i++;
            *security = argv[i];
        } else if (paramcmp(argv[i], "--sig") == 0) {
            /* [--sig <filename>] */
            i++;
            *sig = argv[i];
        } else if (paramcmp(argv[i], "--priv") == 0) {
            /* [--priv <filename>] */
            i++;
            *priv = argv[i];
        } else if (paramcmp(argv[i], "--winternitz") == 0) {
            /* [--winternitz 1|2|4|8] */
            i++;
            if (paramcmp(argv[i], "1") == 0) {
                *w = IQR_LMS_WINTERNITZ_1;
            } else if  (paramcmp(argv[i], "2") == 0) {
                *w = IQR_LMS_WINTERNITZ_2;
            } else if  (paramcmp(argv[i], "4") == 0) {
                *w = IQR_LMS_WINTERNITZ_4;
            } else if  (paramcmp(argv[i], "8") == 0) {
                *w = IQR_LMS_WINTERNITZ_8;
            } else {
                usage();
                return IQR_EBADVALUE;
            }
        } else if (paramcmp(argv[i], "--height") == 0) {
            /* [--height 5|10|20] */
            i++;
            if (paramcmp(argv[i], "5") == 0) {
                *height = IQR_LMS_HEIGHT_5;
            } else if  (paramcmp(argv[i], "10") == 0) {
                *height = IQR_LMS_HEIGHT_10;
            } else if  (paramcmp(argv[i], "20") == 0) {
                *height = IQR_LMS_HEIGHT_20;
            } else {
                usage();
                return IQR_EBADVALUE;
            }
        } else if (paramcmp(argv[i], "--q") == 0) {
            /* [--q <number>] */
            i++;

            char *end = NULL;
            long tmp = strtol(argv[i], &end, 10);
            if (tmp == LONG_MAX || tmp == LONG_MIN) {
                return IQR_EBADVALUE;
            }

            if (tmp < 0) {
                return IQR_EOUTOFRANGE;
            }

            *q = (uint32_t)tmp;
        } else if (paramcmp(argv[i], "--message") == 0) {
           /* [--message <filename>] */
           i++;
           *message = argv[i];
        }
        i++;
    }

    if (*q == UINT32_MAX) {
        fprintf(stderr, "Please provide a q parameter: --q <number>.\n");
        return IQR_EOUTOFRANGE;
    }

    return IQR_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Secure (not really) memset().
// ---------------------------------------------------------------------------------------------------------------------------------

static void *secure_memset(void *b, int c, size_t len)
{
    /** This memset() is NOT secure. It could and probably will be optimized out by the compiler. There isn't a secure,
     * portable memset() available before C11 which provides memset_s(). Windows also provides SecureZeroMemory().
     *
     * This is just for sample purposes, do your own due diligence when choosing a secure memset() so you can securely
     * clear sensitive data.
     */
    return memset(b, c, len);
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Executable entry point.
// ---------------------------------------------------------------------------------------------------------------------------------

int main(int argc, const char **argv)
{
    /* The security string is an identifier for the private key. This
     * value must be distinct from all other identifiers and should be chosen
     * via a pseudorandom function. See section 3.2 of the Hash-Based
     * Signatures IETF specification (McGraw & Curcio).
     */

    /* Default values.  Please adjust the usage() message if you make changes
     *  here.
     */
    const char *security = "** ISARA LMS KEY IDENTIFIER ***";
    const char *sig = "sig.dat";
    const char *priv = "priv.key";
    const char *message = "message.dat";
    iqr_LMSWinternitz w = IQR_LMS_WINTERNITZ_4;
    iqr_LMSHeight height =  IQR_LMS_HEIGHT_5;
    uint32_t q = 0;

    iqr_Context *ctx = NULL;
    iqr_RNG *rng = NULL;
    uint8_t *digest = NULL;

    /* If the command line arguments were not sane, this function will exit
     * the process.
     */
    iqr_retval ret = parse_commandline(argc, argv, &security, &sig, &priv, &q, &w, &height, &message);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], security, sig, priv, w, height, q, message);

    /* IQR initialization that is not specific to LMS. */
    ret = init_toolkit(&ctx, &rng, message, &digest);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* This function showcases the usage of LMS signing.
     */
    ret = showcase_lms_sign(ctx, rng, (const uint8_t *)security, strlen(security), w, height, digest, priv, q, sig);

cleanup:
    iqr_RNGDestroy(&rng);
    iqr_DestroyContext(&ctx);
    free(digest);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
