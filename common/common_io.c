/** @file common_io.c
 *
 * @brief Common stdio I/O operations for samples.
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

#include "isara_samples.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

// ---------------------------------------------------------------------------------------------------------------------------------
// Generic POSIX file stream I/O operations.
// ---------------------------------------------------------------------------------------------------------------------------------

iqr_retval save_data(const char *fname, const uint8_t *data, size_t data_size)
{
    FILE *fp = fopen(fname, "wb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", fname, strerror(errno));
        return IQR_EBADVALUE;
    }

    iqr_retval ret = IQR_OK;
    size_t ret_write = fwrite(data, data_size, 1, fp);
    if (ret_write != 1) {
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

iqr_retval load_data(const char *fname, uint8_t **data, size_t *data_size)
{
    iqr_retval ret = IQR_OK;

    FILE *fp = fopen(fname, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", fname, strerror(errno));
        return IQR_EBADVALUE;
    }

    /* Obtain file size. */
    int ret_seek = fseek(fp , 0 , SEEK_END);
    if (ret_seek != 0) {
        fprintf(stderr, "Failed on fseek(): %s\n", strerror(errno));
        ret = IQR_EBADVALUE;
        goto end;
    }

#if defined(_WIN32) || defined(_WIN64)
    const int64_t tmp_size64 = (int64_t)_ftelli64(fp);

    if (tmp_size64 < 0) {
        fprintf(stderr, "Failed on _ftelli64(): %s\n", strerror(errno));
        ret = IQR_EBADVALUE;
        goto end;
    } else if ((uint64_t)tmp_size64 > (uint64_t)SIZE_MAX) {
        /* On 32-bit systems, we cannot allocate enough memory for large key files. */
        ret = IQR_ENOMEM;
        goto end;
    }

    /* Due to a bug in GCC 7.2, it is necessary to make tmp_size volatile.
     * Otherwise, the variable is removed by the compiler and tmp_size64 is used
     * instead. This causes the calloc() call further down to raise a compiler
     * warning.
     */
    volatile size_t tmp_size = (size_t)tmp_size64;
#else
    const int64_t tmp_size64 = (int64_t)ftell(fp);

    if (tmp_size64 < 0) {
        fprintf(stderr, "Failed on ftell(): %s\n", strerror(errno));
        ret = IQR_EBADVALUE;
        goto end;
    } else if ((uint64_t)tmp_size64 > (uint64_t)SIZE_MAX) {
        /* On 32-bit systems, we cannot allocate enough memory for large key files. */
        ret = IQR_ENOMEM;
        goto end;
    }

    const size_t tmp_size = (size_t)tmp_size64;
#endif

    rewind(fp);

    if (tmp_size > 0) {
        /* calloc with a param of 0 could return a pointer or NULL depending on
         * implementation, so skip all this when the size is 0 so we
         * consistently return NULL with a size of 0. In some samples it's
         * useful to take empty files as input so users can pass NULL or 0 for
         * optional parameters.
         */
        uint8_t *tmp = calloc(1, tmp_size);
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

        *data_size = tmp_size;
        *data = tmp;

        fprintf(stdout, "Successfully loaded %s (%zu bytes)\n", fname, *data_size);
    } else {
        *data_size = 0;
        *data = NULL;

        fprintf(stdout, "%s is empty.\n", fname);
    }

end:
    fclose(fp);
    fp = NULL;
    return ret;
}
