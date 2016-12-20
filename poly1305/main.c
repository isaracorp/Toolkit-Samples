/** @file main.c Perform ChaCha20-Poly1305-AEAD encryption using the Toolkit.
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
#include "iqr_mac.h"
#include "iqr_retval.h"

/* Poly1305 keys must be 32 bytes. */
#define POLY1305_KEY_SIZE 32

/* Poly1305 tags are 16 bytes. */
#define POLY1305_TAG_SIZE 16

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
// This function showcases Poly1305 tag creation.
// ---------------------------------------------------------------------------------------------------------------------------------

static iqr_retval showcase_poly1305(const iqr_Context *ctx, const uint8_t *key_data, size_t key_size,
    const struct file_list *files, const char *tag_file)
{
    if (key_size < POLY1305_KEY_SIZE) {
        fprintf(stderr, "Key is %zu bytes, it must be at least %d bytes (only first %d bytes will be used)\n",
            key_size, POLY1305_KEY_SIZE, POLY1305_KEY_SIZE);
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

    uint8_t poly1305_tag[POLY1305_TAG_SIZE];
    size_t poly1305_tag_size = sizeof(poly1305_tag);

    size_t message_size = 0;
    if (files->next == NULL) {
        // Only a single file, use the one-shot Poly1305 function
        ret = load_data(files->filename, &message, &message_size);
        if (ret != IQR_OK) {
            goto end;
        }

        ret = iqr_MACMessage(poly1305_obj, key_data, key_size, message, message_size, poly1305_tag, poly1305_tag_size);
        if (ret != IQR_OK) {
            fprintf(stderr, "Failed on iqr_MACMessage(): %s\n", iqr_StrError(ret));
            goto end;
        }

        fprintf(stdout, "Poly1305 tag has been created from %s\n", files->filename);
    } else {
        // Multiple files, use the updating Poly1305 functions
        ret = iqr_MACBegin(poly1305_obj, key_data, key_size);
        if (ret != IQR_OK) {
            fprintf(stderr, "Failed on iqr_MACBegin(): %s\n", iqr_StrError(ret));
            goto end;
        }

        while (files != NULL) {
            ret = load_data(files->filename, &message, &message_size);
            if (ret != IQR_OK) {
                goto end;
            }

            ret = iqr_MACUpdate(poly1305_obj, message, message_size);
            if (ret != IQR_OK) {
                fprintf(stderr, "Failed on iqr_MACUpdate(): %s\n", iqr_StrError(ret));
                goto end;
            }

            fprintf(stdout, "Poly1305 tag has been updated from %s\n", files->filename);

            free(message);
            message = NULL;

            files = files->next;
        }

        ret = iqr_MACEnd(poly1305_obj, poly1305_tag, poly1305_tag_size);
        if (ret != IQR_OK) {
            fprintf(stderr, "Failed on iqr_MACEnd(): %s\n", iqr_StrError(ret));
            goto end;
        }
    }

    fprintf(stdout, "Poly1305 tag created.\n");

    ret = save_data(tag_file, poly1305_tag, poly1305_tag_size);
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
// Generic POSIX file stream I/O operations.
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
    fprintf(stdout, "poly1305 [--key { string <key> | file <filename> | none }]\n");
    fprintf(stdout, "  [--tag <filename>]  msg1 [msg2 ...]\n");
    fprintf(stdout, "    Defaults are: \n");
    fprintf(stdout, "        --key string \"****** ISARA-POLY1305-KEY *******\"\n");
    fprintf(stdout, "        --tag tag.dat\n");
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Report the chosen runtime parameters.
// ---------------------------------------------------------------------------------------------------------------------------------

static void preamble(const char *cmd, const uint8_t *key, const char *key_file, const struct file_list *files, const char *tag)
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
    while (files != NULL) {
        fprintf(stdout, "      %s\n", files->filename);
        files = files->next;
    }
    fprintf(stdout, "    tag file: %s\n", tag);
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

static iqr_retval parse_commandline(int argc, const char **argv, const uint8_t **key, const char **key_file,
    struct file_list **files, const char **tag_file)
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
        if (paramcmp(argv[i], "--key") == 0) {
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
            /* [--tag <filename>] */
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
    const uint8_t *key = (const uint8_t *)"****** ISARA-POLY1305-KEY *******";
    const char *key_file = NULL;
    uint8_t *loaded_key = NULL;
    struct file_list *files = NULL;
    const char *tag_file = "tag.dat";

    /* If the command line arguments were not sane, this function will return
     * an error.
     */
    iqr_retval ret = parse_commandline(argc, argv, &key, &key_file, &files, &tag_file);
    if (ret != IQR_OK) {
        return EXIT_FAILURE;
    }

    /* Make sure the user understands what we are about to do. */
    preamble(argv[0], key, key_file, files, tag_file);

    /* IQR initialization that is not specific to Poly1305. */
    iqr_Context *ctx = NULL;
    ret = init_toolkit(&ctx);
    if (ret != IQR_OK) {
        goto cleanup;
    }

    /* Decide whether we're using a key from the command line
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

    /* This function showcases the usage of Poly1305 tag creation.
     */
    ret = showcase_poly1305(ctx, key, key_size, files, tag_file);

    /* Poly1305 keys are private, sensitive data, be sure to clear memory containing them when you're done */
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
