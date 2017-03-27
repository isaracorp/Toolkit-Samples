/** @file main.c Perform decryption using the toolkit's ChaCha20 scheme.
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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iqr_chacha20.h"
#include "iqr_context.h"
#include "iqr_retval.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Function Declarations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval save_data(const char *fname, const uint8_t *data, size_t data_size);
static iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size);
static void *secure_memset(void *b, int c, size_t len);

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases ChaCha20 decryption.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_chacha20_decrypt(const uint8_t *key_data, size_t key_size, const uint8_t *nonce_data, size_t nonce_size,
    uint32_t counter, const uint8_t *ciphertext_data, size_t ciphertext_size, const char *plaintext)
{
    size_t plaintext_size = ciphertext_size;
    uint8_t *plaintext_data = calloc(1, plaintext_size);
    if (plaintext_data == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        return IQR_ENOMEM;
    }

    iqr_retval ret = iqr_ChaCha20Decrypt(key_data, key_size, nonce_data, nonce_size, counter, ciphertext_data, ciphertext_size,
        plaintext_data, plaintext_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_ChaCha20Decrypt(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "ChaCha20 decrypt completed.\n");

    ret = save_data(plaintext, plaintext_data, plaintext_size);
    if (ret != IQR_OK) {
        goto end;
    }

    fprintf(stdout, "Plaintext has been saved to disk.\n");

end:
    free(plaintext_data);
    plaintext_data = NULL;
    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// These functions are designed to help the end user understand how to use
// this sample and hold little value to the developer trying to learn how to
// use the toolkit.
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
//  --------------------------------------------------------------------------------------------------------------------------------

static void usage(void)
{
    fprintf(stdout, "chacha20_decrypt [--key <filename>] [--nonce <filename>]\n"
        "  [--initial_counter <counter>] [--ciphertext <filename>]\n"
        "  [--plaintext <filename>]\n");
    fprintf(stdout, "    Defaults are: \n");
    fprintf(stdout, "        --key key.dat\n");
    fprintf(stdout, "        --nonce nonce.dat\n");
    fprintf(stdout, "        --initial_counter 0\n");
    fprintf(stdout, "        --ciphertext ciphertext.dat\n");
    fprintf(stdout, "        --plaintext plaintext.dat\n");
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, const char *key, const char *nonce, uint32_t counter,
    const char *ciphertext, const char *plaintext)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    fprintf(stdout, "    key file: %s\n", key);
    fprintf(stdout, "    nonce file: %s\n", nonce);
    fprintf(stdout, "    initial counter: %u\n", counter);
    fprintf(stdout, "    ciphertext file: %s\n", ciphertext);
    fprintf(stdout, "    plaintext file: %s\n", plaintext);
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

/* Parse a parameter string which is supposed to be a positive integer
 * and return the value or -1 if the string is not properly formatted.
 */
static int32_t get_positive_int_param(const char *p) {
    char *end = NULL;
    errno = 0;
    const long l = strtol(p, &end, 10);
    // Check for conversion errors.
    if (errno != 0) {
        return -1;
    }
    // Check that the string contained only a number and nothing else.
    if (end == NULL || end == p || *end != '\0' ) {
        return -1;
    }
    if (l < 0 || l > INT_MAX) {
        return -1;
    }
    return (int32_t)l;
}

static iqr_retval parse_commandline(int argc, const char **argv, const char **key, const char **nonce, uint32_t *counter,
    const char **ciphertext, const char **plaintext)
{
    int i = 1;
    while (i != argc) {
        if (i + 2 > argc) {
            usage();
            return IQR_EBADVALUE;
        }
        if (paramcmp(argv[i], "--key") == 0) {
            /* [--key <filename>] */
            i++;
            *key = argv[i];
        } else if (paramcmp(argv[i], "--nonce") == 0) {
            /* [--nonce <filename>] */
            i++;
            *nonce = argv[i];
        } else if (paramcmp(argv[i], "--initial_counter") == 0) {
            /* [--initial_counter <counter>] */
            i++;
            int32_t c = get_positive_int_param(argv[i]);
            if (c < 0) {
                usage();
                return IQR_EBADVALUE;
            }
            *counter = (uint32_t)c;
        } else if (paramcmp(argv[i], "--ciphertext") == 0) {
            /* [--ciphertext <filename>] */
            i++;
            *ciphertext = argv[i];
        } else if (paramcmp(argv[i], "--plaintext") == 0) {
            /* [--plaintext <filename>] */
            i++;
            *plaintext = argv[i];
        } else {
            usage();
            return IQR_EBADVALUE;
        }
        i++;
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
    /* Default values.  Please adjust the usage() message if you make changes
     * here.
     */
    const char *key = "key.dat";
    const char *nonce = "nonce.dat";
    uint32_t counter = 0;
    const char *ciphertext = "ciphertext.dat";
    const char *plaintext = "plaintext.dat";

    uint8_t *key_data = NULL;
    size_t key_size = 0;
    uint8_t *nonce_data = NULL;
    uint8_t *ciphertext_data = NULL;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &key, &nonce, &counter, &ciphertext, &plaintext);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], key, nonce, counter, ciphertext, plaintext);

    /* No IQR initialization is needed for ChaCha20 */

    ret = load_data(key, &key_data, &key_size);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    size_t nonce_size = 0;
    ret = load_data(nonce, &nonce_data, &nonce_size);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    size_t ciphertext_size = 0;
    ret = load_data(ciphertext, &ciphertext_data, &ciphertext_size);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /** This function showcases the usage of ChaCha20 decryption.
     */
    ret = showcase_chacha20_decrypt(key_data, key_size, nonce_data, nonce_size, counter, ciphertext_data, ciphertext_size,
        plaintext);

cleanup:
    free(ciphertext_data);
    ciphertext_data = NULL;
    free(nonce_data);
    nonce_data = NULL;
    /* Keys are private, sensitive data, be sure to clear memory containing them when you're done */
    if (key_data != NULL) {
        secure_memset(key_data, 0, key_size);
    }
    free(key_data);
    key_data = NULL;
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
