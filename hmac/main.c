/** @file main.c
 *
 * @brief Produce a MAC tag using the toolkit's HMAC scheme.
 *
 * @copyright Copyright (C) 2016-2019, ISARA Corporation
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

#include "iqr_context.h"
#include "iqr_hash.h"
#include "iqr_mac.h"
#include "iqr_retval.h"
#include "isara_samples.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Document the command-line arguments.
//  --------------------------------------------------------------------------------------------------------------------------------

static const char *usage_msg =
"hmac [--hash sha2-256|sha2-384|sha2-512|\n"
"  sha3-256|sha3-512]\n"
"  [--key { string <key> | file <filename> }]\n"
"  [--tag <filename>] msg1 [msg2 ...]\n"
"    Defaults are: \n"
"        --hash sha2-256\n"
"        --key string *********ISARA-HMAC-KEY*********\n"
"        --tag tag.dat\n";

// ---------------------------------------------------------------------------------------------------------------------------------
// Structure Declarations.
// ---------------------------------------------------------------------------------------------------------------------------------

struct file_list {
    const char *filename;
    struct file_list *next;
};

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases HMAC tag creation.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_hmac(const iqr_Context *ctx, iqr_HashAlgorithmType hash, const uint8_t *key, size_t key_size,
    const struct file_list *files, const char *tag_file)
{
    iqr_MAC *hmac = NULL;
    iqr_retval ret = iqr_MACCreateHMAC(ctx, hash, &hmac);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_MACCreateHMAC(): %s\n", iqr_StrError(ret));
        return ret;
    }

    size_t min_key_size = 0;
    uint8_t *tag = NULL;
    uint8_t *data = NULL;

    ret = iqr_MACGetKeySize(hmac, &min_key_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_MACGetKeySize(): %s\n", iqr_StrError(ret));
        goto end;
    }

    if (key_size < min_key_size) {
        fprintf(stderr, "Key is %zu bytes, it must be at least %zu bytes.\n", key_size, min_key_size);
        goto end;
    }

    size_t tag_size = 0;
    ret = iqr_MACGetTagSize(hmac, &tag_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_MACGetTagSize(): %s\n", iqr_StrError(ret));
        goto end;
    }
    tag = calloc(1, tag_size);
    if (tag == NULL) {
        fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
        ret = IQR_ENOMEM;
        goto end;
    }

    fprintf(stdout, "HMAC object has been created.\n");

    size_t data_size = 0;
    if (files->next == NULL) {
        // Only a single file, use the one-shot HMAC function.
        ret = load_data(files->filename, &data, &data_size);
        if (ret != IQR_OK) {
            goto end;
        }

        ret = iqr_MACMessage(hmac, key, key_size, data, data_size, tag, tag_size);
        if (ret != IQR_OK) {
            fprintf(stderr, "Failed on iqr_MACMessage(): %s\n", iqr_StrError(ret));
            goto end;
        }

        fprintf(stdout, "HMAC has been created from %s\n", files->filename);
    } else {
        // Multiple files, use the updating HMAC functions.
        ret = iqr_MACBegin(hmac, key, key_size);
        if (ret != IQR_OK) {
            fprintf(stderr, "Failed on iqr_MACBegin(): %s\n", iqr_StrError(ret));
            goto end;
        }

        while (files != NULL) {
            ret = load_data(files->filename, &data, &data_size);
            if (ret != IQR_OK) {
                goto end;
            }

            ret = iqr_MACUpdate(hmac, data, data_size);
            if (ret != IQR_OK) {
                fprintf(stderr, "Failed on iqr_MACUpdate(): %s\n", iqr_StrError(ret));
                goto end;
            }

            fprintf(stdout, "HMAC has been updated from %s\n", files->filename);

            free(data);
            data = NULL;

            files = files->next;
        }

        ret = iqr_MACEnd(hmac, tag, tag_size);
        if (ret != IQR_OK) {
            fprintf(stderr, "Failed on iqr_MACEnd(): %s\n", iqr_StrError(ret));
            goto end;
        }
    }

    fprintf(stdout, "Tag has been calculated.\n");

    ret = save_data(tag_file, tag, tag_size);
    if (ret != IQR_OK) {
        goto end;
    }

    fprintf(stdout, "Tag has been saved to disk.\n");

end:
    free(data);
    data = NULL;
    iqr_MACDestroy(&hmac);
    free(tag);
    tag = NULL;
    return ret;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// This next section of code is related to the toolkit, but is not specific to
// HMAC.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval init_toolkit(iqr_Context **ctx, iqr_HashAlgorithmType hash, const iqr_HashCallbacks *cb)
{
    /* Create a Context. */
    iqr_retval ret = iqr_CreateContext(ctx);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_CreateContext(): %s\n", iqr_StrError(ret));
        return ret;
    }

    /* This sets the hashing functions that will be used globally. */
    ret = iqr_HashRegisterCallbacks(*ctx, hash, cb);
    if (ret != IQR_OK) {
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

static void preamble(const char *cmd, iqr_HashAlgorithmType hash, const uint8_t *key, const char *key_file,
    const struct file_list *files, const char *tag_file)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);

    if (IQR_HASHALGO_SHA2_256 == hash) {
        fprintf(stdout, "    hash algorithm: IQR_HASHALGO_SHA2_256\n");
    } else if (IQR_HASHALGO_SHA2_384 == hash) {
        fprintf(stdout, "    hash algorithm: IQR_HASHALGO_SHA2_384\n");
    } else if (IQR_HASHALGO_SHA2_512 == hash) {
        fprintf(stdout, "    hash algorithm: IQR_HASHALGO_SHA2_512\n");
    } else if (IQR_HASHALGO_SHA3_256 == hash) {
        fprintf(stdout, "    hash algorithm: IQR_HASHALGO_SHA3_256\n");
    } else if (IQR_HASHALGO_SHA3_512 == hash) {
        fprintf(stdout, "    hash algorithm: IQR_HASHALGO_SHA3_512\n");
    }
    if (key != NULL) {
        fprintf(stdout, "    key: %s\n", key);
    } else if (key_file != NULL) {
        fprintf(stdout, "    key file: %s\n", key_file);
    } else {
        fprintf(stdout, "    no key\n");
    }
    fprintf(stdout, "    data file(s):\n");
    while (files != NULL) {
        fprintf(stdout, "      %s\n", files->filename);
        files = files->next;
    }
    fprintf(stdout, "    output tag file: %s\n", tag_file);
    fprintf(stdout, "\n");
}

static iqr_retval parse_commandline(int argc, const char **argv, iqr_HashAlgorithmType *hash, const iqr_HashCallbacks **cb,
    const uint8_t **key, const char **key_file, bool *default_key, struct file_list **files, const char **tag_file)
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
            struct file_list *tail = NULL;
            for (; i < argc; i++) {
                struct file_list *tmp = calloc(1, sizeof(*tmp));
                if (tmp == NULL) {
                    fprintf(stderr, "Failed on calloc(): %s\n", strerror(errno));
                    return IQR_EBADVALUE;
                }
                tmp->filename = argv[i];
                if (*files == NULL) {
                    *files = tmp;
                } else {
                    tail->next = tmp;
                }
                tail = tmp;
            }

            return IQR_OK;
        }

        if (i + 2 > argc) {
            fprintf(stdout, "%s", usage_msg);
            return IQR_EBADVALUE;
        }
        if (paramcmp(argv[i], "--hash") == 0) {
            /* [--hash sha2-256|sha2-384|sha2-512|sha3-256|sha3-512]
             */
            i++;
            if (paramcmp(argv[i], "sha2-256") == 0) {
                *hash = IQR_HASHALGO_SHA2_256;
                *cb = &IQR_HASH_DEFAULT_SHA2_256;
            } else if (paramcmp(argv[i], "sha2-384") == 0) {
                *hash = IQR_HASHALGO_SHA2_384;
                *cb = &IQR_HASH_DEFAULT_SHA2_384;
            } else if (paramcmp(argv[i], "sha2-512") == 0) {
                *hash = IQR_HASHALGO_SHA2_512;
                *cb = &IQR_HASH_DEFAULT_SHA2_512;
            } else if (paramcmp(argv[i], "sha3-256") == 0) {
                *hash = IQR_HASHALGO_SHA3_256;
                *cb = &IQR_HASH_DEFAULT_SHA3_256;
            } else if (paramcmp(argv[i], "sha3-512") == 0) {
                *hash = IQR_HASHALGO_SHA3_512;
                *cb = &IQR_HASH_DEFAULT_SHA3_512;
            } else {
                fprintf(stdout, "%s", usage_msg);
                return IQR_EBADVALUE;
            }
        } else if (paramcmp(argv[i], "--key") == 0) {
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
            } else if (paramcmp(param2, "file") == 0) {
                *key = NULL;
                *key_file = argv[i];
            } else {
                fprintf(stdout, "%s", usage_msg);
                return IQR_EBADVALUE;
            }

            *default_key = false;
        } else if (paramcmp(argv[i], "--tag") == 0) {
            /* [--tag <output tag file>] */
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

int main(int argc, const char **argv)
{
    /* Default values. Please adjust the usage message if you make changes
     * here.
     */
    iqr_HashAlgorithmType hash = IQR_HASHALGO_SHA2_256;
    const iqr_HashCallbacks *cb = &IQR_HASH_DEFAULT_SHA2_256;
    const uint8_t *key = (const uint8_t *)"*********ISARA-HMAC-KEY*********";
    const uint8_t *key_48 = (const uint8_t *)"*********ISARA-HMAC-KEY-FOR-384-BIT-SHA*********";
    const uint8_t *key_64 = (const uint8_t *)"*****************ISARA-HMAC-KEY-FOR-512-BIT-SHA*****************";
    const char *tag_file = "tag.dat";
    bool default_key = true;

    const char *key_file = NULL;
    struct file_list *files = NULL;

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &hash, &cb, &key, &key_file, &default_key, &files, &tag_file);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    if (default_key && (hash == IQR_HASHALGO_SHA2_384)) {
        key = key_48;
    }

    if (default_key && (hash == IQR_HASHALGO_SHA2_512 || hash == IQR_HASHALGO_SHA3_512)) {
        key = key_64;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], hash, key, key_file, files, tag_file);

    /* IQR initialization that is not specific to HMAC. */
    iqr_Context *ctx = NULL;
    uint8_t *loaded_key = NULL;
    ret = init_toolkit(&ctx, hash, cb);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /** Decide whether we're using a key from the command line
     * or a file */
    size_t key_size = 0;
    if (key != NULL) {
        key_size = strlen((const char *)key);
    } else if (key_file != NULL) {
        ret = load_data(key_file, &loaded_key, &key_size);
        if (ret != IQR_OK) {
            goto cleanup;
        }
        key = loaded_key;
    }

    /** This function showcases the usage of HMAC tag generation.
     */
    ret = showcase_hmac(ctx, hash, key, key_size, files, tag_file);

    /* HMAC keys are private, sensitive data, be sure to clear memory containing
     * them when you're done.
     */
    if (loaded_key != NULL) {
        secure_memzero(loaded_key, key_size);
    }

cleanup:
    free(loaded_key);
    loaded_key = NULL;
    while (files != NULL) {
        struct file_list *next = files->next;
        free(files);
        files = next;
    }
    files = NULL;

    iqr_DestroyContext(&ctx);

    return (ret == IQR_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
