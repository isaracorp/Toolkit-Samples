/** @file main.c Verify a signature using the toolkit's LMS signature scheme.
 *
 * @copyright Copyright 2016-2017 ISARA Corporation
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
#include "iqr_lms.h"
#include "iqr_retval.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Function Declarations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size);

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the verification of an LMS signature against a
// digest.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_lms_verify(const iqr_Context *ctx, const iqr_LMSWinternitz w, const iqr_LMSHeight height,
    const uint8_t *digest, const char *pub_file, const char *sig_file)
{

    iqr_LMSParams *params = NULL;
    iqr_LMSPublicKey *pub = NULL;

    size_t pub_raw_size = 0;
    uint8_t *pub_raw = NULL;

    size_t sig_size = 0;
    uint8_t *sig = NULL;

    iqr_retval ret = iqr_LMSCreateParams(ctx, w, height, &params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_LMSCreateParams(): %s\n", iqr_StrError(ret));
        goto end;
    }

    /* Load the public key and signature from disk. */
    ret = load_data(pub_file, &pub_raw, &pub_raw_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = load_data(sig_file, &sig, &sig_size);
    if (ret != IQR_OK) {
        goto end;
    }

    /* Import the public key data and create a public key object. */
    ret = iqr_LMSImportPublicKey(params, pub_raw, pub_raw_size, &pub);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_LMSImportPublicKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Public key has been loaded successfully!\n");

    ret = iqr_LMSVerify(pub, digest, IQR_SHA2_256_DIGEST_SIZE, sig, sig_size);
    if (ret == IQR_OK) {
        fprintf(stdout, "LMS verified the signature successfully!\n");
    } else {
        fprintf(stderr, "Failed on iqr_LMSVerify(): %s\n", iqr_StrError(ret));
    }

    iqr_LMSDestroyPublicKey(&pub);

end:
    free(pub_raw);
    free(sig);

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

    /* The LMS scheme will sign a digest of the message, so we need a digest
     * of our message.  This will give us that digest.
     */
    ret = iqr_HashMessage(hash, data, data_size, out_digest, IQR_SHA2_256_DIGEST_SIZE);
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

    /* Before we do any work, lets make sure we can load the message file. */
    ret = load_data(message, &message_raw, &message_raw_size);
    if (ret != IQR_OK) {
        return ret;
    }

    *digest = calloc(1, IQR_SHA2_256_DIGEST_SIZE);
    if (*digest == NULL) {
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
// Generic POSIX file stream I/O operations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size)
{
    FILE *fp = fopen(fname, "rb");
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
    fprintf(stdout, "lms_verify [--sig <filename>] [--pub <filename>]\n"
        "  [--winternitz 1|2|4|8] [--height 5|10|15|20|25]\n"
        "  [--message <filename>]\n");
    fprintf(stdout, "    Defaults are: \n");
    fprintf(stdout, "        --sig sig.dat\n");
    fprintf(stdout, "        --pub pub.key\n");
    fprintf(stdout, "        --winternitz 4\n");
    fprintf(stdout, "        --height 5\n");
    fprintf(stdout, "        --message message.dat\n");
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, const char *sig, const char *pub, const iqr_LMSWinternitz w, const iqr_LMSHeight height,
    const char *message)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    fprintf(stdout, "    signature file: %s\n", sig);
    fprintf(stdout, "    public key file: %s\n", pub);

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
    } else if (IQR_LMS_HEIGHT_15 == height) {
        fprintf(stdout, "    height: IQR_LMS_HEIGHT_15\n");
    } else if (IQR_LMS_HEIGHT_20 == height) {
        fprintf(stdout, "    height: IQR_LMS_HEIGHT_20\n");
    } else if (IQR_LMS_HEIGHT_25 == height) {
        fprintf(stdout, "    height: IQR_LMS_HEIGHT_25\n");
    } else {
        fprintf(stdout, "    height: INVALID\n");
    }
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
    const size_t max_param_size = 32;  // Arbitrary, but reasonable.
    if (strnlen(p1, max_param_size) != strnlen(p2, max_param_size)) {
        return 1;
    }
    return strncmp(p1, p2, max_param_size);
}

static iqr_retval parse_commandline(int argc, const char **argv, const char **sig, const char **pub, iqr_LMSWinternitz *w,
    iqr_LMSHeight *height, const char **message)
{
    int i = 1;
    while (i != argc) {
        if (i + 2 > argc) {
            usage();
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
            } else if  (paramcmp(argv[i], "15") == 0) {
                *height = IQR_LMS_HEIGHT_15;
            } else if  (paramcmp(argv[i], "20") == 0) {
                *height = IQR_LMS_HEIGHT_20;
            } else if  (paramcmp(argv[i], "25") == 0) {
                *height = IQR_LMS_HEIGHT_25;
            } else {
                usage();
                return IQR_EBADVALUE;
            }
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
    /* The security string is an identifier for the private key. This
     * value must be distinct from all other identifiers and should be chosen
     * via a pseudorandom function. See section 3.2 of the Hash-Based
     * Signatures IETF specification (McGraw & Curcio).
     */

    /* Default values.  Please adjust the usage() message if you make changes
     * here. */
    const char *sig = "sig.dat";
    const char *pub = "pub.key";
    const char *message = "message.dat";
    iqr_LMSWinternitz w = IQR_LMS_WINTERNITZ_4;
    iqr_LMSHeight height =  IQR_LMS_HEIGHT_5;

    iqr_Context *ctx = NULL;
    uint8_t *digest = NULL;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &sig, &pub, &w, &height, &message);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], sig, pub, w, height, message);

    /* IQR initialization that is not specific to LMS. */
    ret = init_toolkit(&ctx, message, &digest);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* This function showcases the usage of LMS signature verification.
     */
    ret = showcase_lms_verify(ctx, w, height, digest, pub, sig);

cleanup:
    iqr_DestroyContext(&ctx);
    free(digest);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
