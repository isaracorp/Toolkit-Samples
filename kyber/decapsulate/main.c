/** @file main.c Demonstrate the toolkit's Kyber Key Encapsulation Mechanism.
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "iqr_context.h"
#include "iqr_hash.h"
#include "iqr_kyber.h"
#include "iqr_retval.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Function Declarations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval save_data(const char *fname, const uint8_t *data, size_t data_size);
static iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size);
static void *secure_memset(void *b, int c, size_t len);

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases Kyber decapsulation.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_kyber_decapsulation(const iqr_KyberParams *params, const char *privkey_file,
    const char * ciphertext_file, const char *sharedkey_file)
{
    size_t ciphertext_size = 0;
    size_t privkey_dat_size = 0;

    uint8_t *ciphertext = NULL;
    uint8_t *privkey_dat = NULL;

    uint8_t sharedkey[IQR_KYBER_SHARED_KEY_SIZE];

    iqr_KyberPrivateKey *privkey = NULL;

    iqr_retval ret = load_data(privkey_file, &privkey_dat, &privkey_dat_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = load_data(ciphertext_file, &ciphertext, &ciphertext_size);
    if (ret != IQR_OK) {
        goto end;
    }

    ret = iqr_KyberImportPrivateKey(params, privkey_dat, privkey_dat_size, &privkey);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_KyberImportPrivateKey(): %s\n", iqr_StrError(ret));
        goto end;
    }

    /* Perform Kyber decapsulation. */
    ret = iqr_KyberDecapsulate(privkey, ciphertext, ciphertext_size, sharedkey, sizeof(sharedkey));
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_KyberDecapsulate(): %s\n", iqr_StrError(ret));
        goto end;
    }

    ret = save_data(sharedkey_file, sharedkey, sizeof(sharedkey));
    if (ret != IQR_OK) {
        goto end;
    }

    fprintf(stdout, "Kyber decapsulation completed.\n");

end:
    if (privkey_dat!= NULL) {
        /* (Private) Keys are private, sensitive data, be sure to clear memory
         * containing them when you're done.
         */
        secure_memset(privkey_dat, 0, privkey_dat_size);
    }
    free(ciphertext);
    free(privkey_dat);
    iqr_KyberDestroyPrivateKey(&privkey);

    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases the creation of Kyber parameter structure.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_kyber_params_creation(const iqr_Context *ctx, const iqr_KyberVariant *variant, iqr_KyberParams **params)
{
    /* Create kyber parameters. */
    iqr_retval ret = iqr_KyberCreateParams(ctx, variant, params);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_KyberCreateParams(): %s\n", iqr_StrError(ret));
        return ret;
    }

    fprintf(stdout, "Kyber parameter structure has been created.\n");

    return IQR_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// kyber.
// ---------------------------------------------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------------------------------------------
// Initialize the toolkit by creating a context and registering hash algorithm.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval init_toolkit(iqr_Context **ctx)
{
    /* Create a context. */
    iqr_retval ret = iqr_CreateContext(ctx);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_CreateContext(): %s\n", iqr_StrError(ret));
        return ret;
    }

    fprintf(stdout, "The context has been created.\n");

    return IQR_OK;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// These functions are designed to help the end user use the sample or are
// generic utility functions. This section has little value to the developer
// trying to learn how to use the toolkit.
// ---------------------------------------------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------------------------------------------
// Generic POSIX file stream I/O operations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval save_data(const char *fname, const uint8_t *data, size_t data_size)
{
    FILE *fp = fopen(fname, "wb");
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
        /* calloc() with a param of 0 could return a pointer or NULL depending
         * on implementation, so skip all this when the size is 0 so we
         * consistently return NULL with a size of 0.
         *
         * In some samples it's useful to take empty files as input so users
         * can pass NULL or 0 for optional parameters.
         */
        tmp = calloc(1, tmp_size);
        if (tmp == NULL) {
            fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
            ret = IQR_EBADVALUE;
            goto end;
        }

        size_t read_size = fread(tmp, 1, tmp_size, fp);;
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
    fprintf(stdout, "Usage:\n");
    fprintf(stdout, "kyber_decapsulate [--security 128|224] [--priv <filename>] [--ciphertext <filename>]\n"
            "  [--shared <filename>]\n");
    fprintf(stdout, "    Default for the sample (when no option is specified):\n");
    fprintf(stdout, "        --security 128\n");
    fprintf(stdout, "        --priv priv.key\n");
    fprintf(stdout, "        --ciphertext ciphertext.dat\n");
    fprintf(stdout, "        --shared shared.key\n");
}

/* Tests if two parameters match.
 * Returns 0 if the two parameter match, non-zero otherwise.
 * Parameters are expected to be less than 32 characters in length.
 */
static int paramcmp(const char *p1 , const char *p2)
{
    const size_t max_param_size = 32;
    if (strnlen(p1, max_param_size) != strnlen(p2, max_param_size)) {
        return 1;
    }
    return strncmp(p1, p2, max_param_size);
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, const char *priv, const char *cipher, const char *sharedkey)
{
    fprintf(stdout, "Running %s with the following parameters:\n", cmd);
    fprintf(stdout, "    private key file: %s\n", priv);
    fprintf(stdout, "    ciphertext file: %s\n", cipher);
    fprintf(stdout, "    shared key file: %s\n", sharedkey);
}

/* Parse the command line options. */
static iqr_retval parse_commandline(int argc, const char **argv, const iqr_KyberVariant **variant, const char **private_key_file,
    const char **ciphertext_file, const char **sharedkey_file)
{
    int i = 1;
    while (i != argc) {
        if (paramcmp(argv[i], "--priv") == 0) {
            /* [--priv <filename>] */
            i++;
            *private_key_file = argv[i];
        } else if (paramcmp(argv[i], "--ciphertext") == 0) {
            /* [--ciphertext <filename>] */
            i++;
            *ciphertext_file = argv[i];
        } else if (paramcmp(argv[i], "--shared") == 0) {
            /* [--shared <filename>] */
            i++;
            *sharedkey_file = argv[i];
        } else if (paramcmp(argv[i], "--security") == 0) {
            /* [--security 128|224] */
            i++;
            if (paramcmp(argv[i], "128") == 0) {
                *variant = &IQR_KYBER_128;
            } else if  (paramcmp(argv[i], "224") == 0) {
                *variant = &IQR_KYBER_224;
            } else {
                usage();
                return IQR_EBADVALUE;
            }
        } else {
            usage();
            return IQR_EBADVALUE;
        }
        i++;
    }
    return IQR_OK;
}

static void *secure_memset(void *b, int c, size_t len)
{
    /** This memset() is NOT secure. It could and probably will be optimized
     * out by the compiler. There isn't a secure, portable memset() available
     * before C11 which provides memset_s(). Windows also provides
     * SecureZeroMemory().
     *
     * This is just for sample purposes, do your own due diligence when
     * choosing a secure memset() so you can securely clear sensitive data.
     */
    return memset(b, c, len);
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Executable entry point.
// ---------------------------------------------------------------------------------------------------------------------------------

int main(int argc, const char **argv)
{
    iqr_Context * ctx = NULL;
    iqr_KyberParams *parameters = NULL;
    const iqr_KyberVariant *variant = &IQR_KYBER_128;

    /* Default values.  Please adjust the usage() message if you make changes
     * here.
     */
    const char *private_key_file = "priv.key";
    const char *ciphertext_file = "ciphertext.dat";
    const char *sharedkey_file = "shared.key";

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &variant, &private_key_file, &ciphertext_file, &sharedkey_file);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Show the parameters for the program. */
    preamble(argv[0], private_key_file, ciphertext_file, sharedkey_file);

    /* IQR toolkit initialization. */
    ret = init_toolkit(&ctx);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase the creation of Kyber parameter structure. */
    ret = showcase_kyber_params_creation(ctx, variant, &parameters);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Showcase Kyber decapsulation. */
    ret = showcase_kyber_decapsulation(parameters, private_key_file, ciphertext_file, sharedkey_file);

cleanup:
    iqr_KyberDestroyParams(&parameters);
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
