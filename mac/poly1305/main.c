/** @file main.c
 *
 * @brief Perform ChaCha20-Poly1305-AEAD encryption using the toolkit.
 *
 * @copyright Copyright (C) 2016-2020, ISARA Corporation
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
#include "iqr_mac.h"
#include "iqr_retval.h"
#include "isara_samples.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Document the command-line arguments.
//  --------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"poly1305 [--key { string <key> | file <filename> }]\n"
"  [--tag <filename>]  msgfile1 [msgfile2 ...]\n"
"\n"
"    Defaults:\n"
"        --key string \"****** ISARA-POLY1305-KEY ******\"\n"
"        --tag tag.dat\n"
"\n"
"  The key must be 32 or more bytes.\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases Poly1305 tag creation.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_poly1305(const iqr_Context *ctx, const uint8_t *key_data, size_t key_size, char **files,
    size_t num_files, const char *tag_file)
{
    if (key_size < IQR_POLY1305_KEY_SIZE) {
        fprintf(stderr, "Key is %zu bytes, it must be at least %d bytes (only first %d bytes will be used)\n",
            key_size, IQR_POLY1305_KEY_SIZE, IQR_POLY1305_KEY_SIZE);
        return IQR_EINVBUFSIZE;
    }

    uint8_t *message = NULL;
    iqr_MAC *poly1305_obj = NULL;
    iqr_retval ret = iqr_MACCreatePoly1305(ctx, &poly1305_obj);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_MACCreatePoly1305(): %s\n", iqr_StrError(ret));
        goto end;
    }

    fprintf(stdout, "Poly1305 object has been created.\n");

    uint8_t poly1305_tag[IQR_POLY1305_TAG_SIZE] = { 0 };

    size_t message_size = 0;
    if (num_files == 1) {
        // Only a single file, use the one-shot Poly1305 function
        ret = load_data(files[0], &message, &message_size);
        if (ret != IQR_OK) {
            goto end;
        }

        ret = iqr_MACMessage(poly1305_obj, key_data, key_size, message, message_size, poly1305_tag, IQR_POLY1305_TAG_SIZE);
        if (ret != IQR_OK) {
            fprintf(stderr, "Failed on iqr_MACMessage(): %s\n", iqr_StrError(ret));
            goto end;
        }

        fprintf(stdout, "Poly1305 tag has been created from %s\n", files[0]);
    } else {
        // Multiple files, use the updating Poly1305 functions
        ret = iqr_MACBegin(poly1305_obj, key_data, key_size);
        if (ret != IQR_OK) {
            fprintf(stderr, "Failed on iqr_MACBegin(): %s\n", iqr_StrError(ret));
            goto end;
        }

        for (size_t i = 0; i < num_files; i++) {
            ret = load_data(files[i], &message, &message_size);
            if (ret != IQR_OK) {
                goto end;
            }

            ret = iqr_MACUpdate(poly1305_obj, message, message_size);
            if (ret != IQR_OK) {
                fprintf(stderr, "Failed on iqr_MACUpdate(): %s\n", iqr_StrError(ret));
                goto end;
            }

            fprintf(stdout, "Poly1305 tag has been updated from %s\n", files[i]);

            free(message);
            message = NULL;
        }

        ret = iqr_MACEnd(poly1305_obj, poly1305_tag, IQR_POLY1305_TAG_SIZE);
        if (ret != IQR_OK) {
            fprintf(stderr, "Failed on iqr_MACEnd(): %s\n", iqr_StrError(ret));
            goto end;
        }
    }

    fprintf(stdout, "Poly1305 tag created.\n");

    ret = save_data(tag_file, poly1305_tag, IQR_POLY1305_TAG_SIZE);
    if (ret != IQR_OK) {
        goto end;
    }

    fprintf(stdout, "Poly1305 tag has been saved to disk.\n");

end:
    free(message);
    message = NULL;
    iqr_MACDestroy(&poly1305_obj);
    return ret;
}

static iqr_retval init_toolkit(iqr_Context **ctx)
{
    /* Create an IQR Context. */
    iqr_retval ret = iqr_CreateContext(ctx);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_CreateContext(): %s\n", iqr_StrError(ret));
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

static void preamble(const char *cmd, const uint8_t *key, const char *key_file, char **files, size_t num_files, const char *tag)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);
    if (key != NULL) {
        fprintf(stdout, "    key: %s\n", key);
    } else if (key_file != NULL) {
        fprintf(stdout, "    key file: %s\n", key_file);
    } else {
        fprintf(stdout, "    no key\n");
    }
    fprintf(stdout, "    data file(s):\n");
    for (size_t i = 0; i < num_files; i++) {
        fprintf(stdout, "      %s\n", files[i]);
    }
    fprintf(stdout, "    tag file: %s\n", tag);
    fprintf(stdout, "\n");
}

// I'm so very sorry about the ***files there.
static iqr_retval parse_commandline(int argc, char **argv, const uint8_t **key, const char **key_file, char ***files,
    size_t *num_files, const char **tag_file)
{
    int i = 1;
    while (1) {
        if (i == argc) {
            // We need at least one message file.
            fprintf(stdout, "%s", usage_msg);
            return IQR_EBADVALUE;
        }

        if (strncmp(argv[i], "--", 2) != 0) {
            // We got to the end of the "--" parameters, read the message
            // files next.
            *files = &(argv[i]);
            *num_files = argc - i;

            return IQR_OK;
        }

        if (i + 2 > argc) {
            fprintf(stdout, "%s", usage_msg);
            return IQR_EBADVALUE;
        }
        if (paramcmp(argv[i], "--key") == 0) {
            /* [--key { string <key> | file <filename> }] */
            i++;
            if (i + 2 > argc) {
                fprintf(stdout, "%s", usage_msg);
                return IQR_EBADVALUE;
            }

            const char *param2 = argv[i];
            i++;
            if (paramcmp(param2, "string") == 0) {
                *key = (const uint8_t *)argv[i];
                *key_file = NULL;
                if (strnlen((const char *)*key, IQR_POLY1305_KEY_SIZE) < IQR_POLY1305_KEY_SIZE) {
                    return IQR_EBADVALUE;
                }
            } else if (paramcmp(param2, "file") == 0) {
                *key = NULL;
                *key_file = argv[i];
            } else {
                fprintf(stdout, "%s", usage_msg);
                return IQR_EBADVALUE;
            }
        } else if (paramcmp(argv[i], "--tag") == 0) {
            /* [--tag <filename>] */
            i++;
            *tag_file = argv[i];
        } else {
            fprintf(stdout, "%s", usage_msg);
            return IQR_EBADVALUE;
        }
        i++;
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Executable entry point.
// ---------------------------------------------------------------------------------------------------------------------------------

int main(int argc, char **argv)
{
    /* Default values. Please adjust the usage message if you make changes
     * here.
     */
    const uint8_t *key = (const uint8_t *)"****** ISARA-POLY1305-KEY ******";
    const char *tag_file = "tag.dat";

    const char *key_file = NULL;
    uint8_t *loaded_key = NULL;
    char **files = NULL;
    size_t num_files = 0;
    iqr_Context *ctx = NULL;
    size_t key_size = 0;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &key, &key_file, &files, &num_files, &tag_file);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], key, key_file, files, num_files, tag_file);

    /* IQR initialization that is not specific to Poly1305. */
    ret = init_toolkit(&ctx);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Decide whether we're using a key from the command line
     * or a file
     */
    if (key != NULL) {
        key_size = strlen((const char *)key);
    } else if (key_file != NULL) {
        ret = load_data(key_file, &loaded_key, &key_size);
        if (ret != IQR_OK) {
            goto cleanup;
        }
        if (key_size < IQR_POLY1305_KEY_SIZE) {
            fprintf(stderr, "Key file must have at least %d bytes.\n", IQR_POLY1305_KEY_SIZE);
            ret = IQR_EINVBUFSIZE;
            goto cleanup;
        }
        key = loaded_key;
    }

    /* This function showcases the usage of Poly1305 tag creation. */
    ret = showcase_poly1305(ctx, key, key_size, files, num_files, tag_file);

    /* Poly1305 keys are private, sensitive data, be sure to clear memory
     * containing them when you're done.
     */
    if (loaded_key != NULL) {
        secure_memzero(loaded_key, key_size);
    }

cleanup:
    free(loaded_key);
    loaded_key = NULL;
    iqr_DestroyContext(&ctx);
    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
