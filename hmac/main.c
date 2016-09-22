/** @file main.c Produce a MAC tag using the Toolkit's HMAC scheme.
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

#include "iqr_context.h"
#include "iqr_hash.h"
#include "iqr_hmac.h"
#include "iqr_retval.h"

// ---------------------------------------------------------------------------------------------------------------------------------
// Structure Declarations.
// ---------------------------------------------------------------------------------------------------------------------------------

struct file_list {
    const char *filename;
    struct file_list *next;
};

// ---------------------------------------------------------------------------------------------------------------------------------
// Function Declarations.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval save_data(const char *fname, const uint8_t *data, size_t data_size);
static iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size);
static void *secure_memset(void *b, int c, size_t len);

// ---------------------------------------------------------------------------------------------------------------------------------
// This function showcases HMAC tag creation.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_hmac(const iqr_Context *ctx, iqr_HashAlgorithmType hash, const uint8_t *key, size_t key_size,
    const struct file_list *files, const char *tag_file)
{
    iqr_HMAC *hmac = NULL;
    iqr_retval ret = iqr_HMACCreate(ctx, hash, &hmac);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HMACCreate(): %s\n", iqr_StrError(ret));
        return ret;
    }

    uint8_t *tag = NULL;
    uint8_t *data = NULL;

    size_t tag_size = 0;
    ret = iqr_HMACGetTagSize(hmac, &tag_size);
    if (ret != IQR_OK) {
        fprintf(stderr, "Failed on iqr_HMACGetTagSize(): %s\n", iqr_StrError(ret));
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
        // Only a single file, use the one-shot HMAC function
        ret = load_data(files->filename, &data, &data_size);
        if (ret != IQR_OK) {
            goto end;
        }

        ret = iqr_HMACMessage(hmac, key, key_size, data, data_size, tag, tag_size);
        if (ret != IQR_OK) {
            fprintf(stderr, "Failed on iqr_HMACMessage(): %s\n", iqr_StrError(ret));
            goto end;
        }

        fprintf(stdout, "HMAC has been created from %s\n", files->filename);
    } else {
        // Multiple files, use the updating HMAC functions
        ret = iqr_HMACBegin(hmac, key, key_size);
        if (ret != IQR_OK) {
            fprintf(stderr, "Failed on iqr_HMACBegin(): %s\n", iqr_StrError(ret));
            goto end;
        }

        while (files != NULL) {
            ret = load_data(files->filename, &data, &data_size);
            if (ret != IQR_OK) {
                goto end;
            }

            ret = iqr_HMACUpdate(hmac, data, data_size);
            if (ret != IQR_OK) {
                fprintf(stderr, "Failed on iqr_HMACUpdate(): %s\n", iqr_StrError(ret));
                goto end;
            }

            fprintf(stdout, "HMAC has been updated from %s\n", files->filename);

            free(data);
            data = NULL;

            files = files->next;
        }

        ret = iqr_HMACEnd(hmac, tag, tag_size);
        if (ret != IQR_OK) {
            fprintf(stderr, "Failed on iqr_HMACEnd(): %s\n", iqr_StrError(ret));
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
    iqr_HMACDestroy(&hmac);
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
//  --------------------------------------------------------------------------------------------------------------------------------

static void usage(void)
{
    fprintf(stdout, "hmac [--hash sha2-256|sha2-512|sha3-256|sha3-512]\n"
        "  [--key { string <key> | file <filename> | none }]\n"
        "  [--tag <filename>] msg1 [msg2 ...]\n");
    fprintf(stdout, "    Defaults are: \n");
    fprintf(stdout, "        --hash sha2-256\n");
    fprintf(stdout, "        --key string ISARA-HMAC-KEY\n");
    fprintf(stdout, "        --tag tag.dat\n");
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, iqr_HashAlgorithmType hash, const uint8_t *key, const char *key_file,
    const struct file_list *files, const char *tag_file)
{
    fprintf(stdout, "Running %s with the following parameters...\n", cmd);

    if (IQR_HASHALGO_SHA2_256 == hash) {
        fprintf(stdout, "    hash algorithm: IQR_HASHALGO_SHA2_256\n");
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

static iqr_retval parse_commandline(int argc, const char **argv, iqr_HashAlgorithmType *hash, const iqr_HashCallbacks **cb,
    const uint8_t **key, const char **key_file, struct file_list **files, const char **tag_file)
{
    int i = 1;
    while (1) {
        if (i == argc) {
            // We need at least one message file.
            usage();
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
            usage();
            return IQR_EBADVALUE;
        }
        if (paramcmp(argv[i], "--hash") == 0) {
            /* [--hash sha2-256|sha2-512|sha3-256|sha3-512] */
            i++;
            if (paramcmp(argv[i], "sha2-256") == 0) {
                *hash = IQR_HASHALGO_SHA2_256;
                *cb = &IQR_HASH_DEFAULT_SHA2_256;
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
                usage();
                return IQR_EBADVALUE;
            }
        } else if (paramcmp(argv[i], "--key") == 0) {
            /* [--key { string <key> | file <filename> | none }] */
            i++;
            if (paramcmp(argv[i], "none") == 0) {
                *key = NULL;
                *key_file = NULL;
            } else {
                if (i + 2 > argc) {
                    usage();
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
                    usage();
                    return IQR_EBADVALUE;
                }
            }
        } else if (paramcmp(argv[i], "--tag") == 0) {
            /* [--tag <output tag file>] */
            i++;
            *tag_file = argv[i];
        } else {
            usage();
            return IQR_EBADVALUE;
        }
        i++;
    }
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
    iqr_HashAlgorithmType hash = IQR_HASHALGO_SHA2_256;
    const iqr_HashCallbacks *cb = &IQR_HASH_DEFAULT_SHA2_256;
    const uint8_t *key = (const uint8_t *)"ISARA-HMAC-KEY";
    const char *key_file = NULL;
    struct file_list *files = NULL;
    const char *tag_file = "tag.dat";

    /* If the command line arguments were not sane, this function will exit
     * the process.
     */
    iqr_retval ret = parse_commandline(argc, argv, &hash, &cb, &key, &key_file, &files, &tag_file);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
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

    /* HMAC keys are private, sensitive data, be sure to clear memory containing them when you're done */
    if (loaded_key != NULL) {
        secure_memset(loaded_key, 0, key_size);
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
