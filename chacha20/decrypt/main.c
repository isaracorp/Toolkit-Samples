/** @file main.c
 *
 * @brief Perform decryption using the toolkit's ChaCha20 scheme.
 *
 * @copyright Copyright (C) 2016-2023, ISARA Corporation, All Rights Reserved.
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
#include "isara_samples.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Document the command-line arguments.
//  --------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"chacha20_decrypt [--key <filename>] [--nonce <filename>]\n"
"  [--initial_counter <counter>] [--ciphertext <filename>]\n"
"  [--plaintext <filename>]\n"
"\n"
"    Defaults:\n"
"        --key key.dat\n"
"        --nonce nonce.dat\n"
"        --initial_counter 0\n"
"        --ciphertext ciphertext.dat\n"
"        --plaintext plaintext.dat\n";

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
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, const char *key, const char *nonce, uint32_t counter, const char *ciphertext,
    const char *plaintext)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    fprintf(stdout, "    key file: %s\n", key);
    fprintf(stdout, "    nonce file: %s\n", nonce);
    fprintf(stdout, "    initial counter: %u\n", counter);
    fprintf(stdout, "    ciphertext file: %s\n", ciphertext);
    fprintf(stdout, "    plaintext file: %s\n", plaintext);
    fprintf(stdout, "\n");
}

/* Parse a parameter string which is supposed to be a positive integer
 * and return the value or -1 if the string is not properly formatted.
 */
static int32_t get_positive_int_param(const char *p)
{
    char *end = NULL;
    errno = 0;
    const long l = strtol(p, &end, 10);
    // Check for conversion errors.
    if (errno != 0) {
        return -1;
    }
    // Check that the string contained only a number and nothing else.
    if (end == NULL || end == p || *end != '\0') {
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
            fprintf(stdout, "%s", usage_msg);
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
                fprintf(stdout, "%s", usage_msg);
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

    /* This function showcases the usage of ChaCha20 decryption. */
    ret = showcase_chacha20_decrypt(key_data, key_size, nonce_data, nonce_size, counter, ciphertext_data, ciphertext_size,
        plaintext);

cleanup:
    free(ciphertext_data);
    ciphertext_data = NULL;
    free(nonce_data);
    nonce_data = NULL;
    /* Keys are private, sensitive data, be sure to clear memory containing them
     * when you're done.
     */
    if (key_data != NULL) {
        secure_memzero(key_data, key_size);
    }
    free(key_data);
    key_data = NULL;
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
