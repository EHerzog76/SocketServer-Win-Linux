/*
 * Copyright (c), Microsoft Open Technologies, Inc.
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define __WIN32_API

#include "Win32_APIs.h"
#include <errno.h>

/* Replace MS C rtl rand which is 15bit with 32 bit */
int replace_random() {
    unsigned int x = 0;
    if (RtlGenRandom == NULL) {
        // Load proc if not loaded
        HMODULE lib = LoadLibraryA("advapi32.dll");
        RtlGenRandom = (RtlGenRandomFunc) GetProcAddress(lib, "SystemFunction036");
        if (RtlGenRandom == NULL) return 1;
    }
    RtlGenRandom(&x, sizeof(unsigned int));
    return (int) (x >> 1);
}

#if !defined(_WIN32)
/* Rename which works on Windows when file exists */
int replace_rename(const char *src, const char *dst) {
    int retries = 50;
    while (1) {
        if (MoveFileExA(src, dst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH)) {
            return 0;
        } else {
            errno = GetLastError();
            // Anti-virus may lock file - error code 5.
            if (errno != 5) {
                break;
            }
            retries--;
            if (retries == 0) {
                break;
            }
            Sleep(10);
        }
    }
    // On error we will return generic error code without GetLastError()
    return -1;
}

int truncate(const char *path, PORT_LONGLONG length) {
    LARGE_INTEGER newSize;
    HANDLE toTruncate = CreateFileA(path,
                                    GENERIC_READ | GENERIC_WRITE,
                                    FILE_SHARE_WRITE | FILE_SHARE_READ,
                                    NULL,
                                    OPEN_EXISTING,
                                    0,
                                    NULL);
    if (toTruncate != INVALID_HANDLE_VALUE) {
        int result = 0;
        newSize.QuadPart = length;
        if (FALSE == (SetFilePointerEx(toTruncate, newSize, NULL, FILE_BEGIN)
                      && SetEndOfFile(toTruncate))) {
            errno = ENOENT;
            result = -1;
        }
        CloseHandle(toTruncate);
        return result;
    } else {
        errno = ENOENT;
        return -1;
    }
}
#endif

/* Convert from "a.b.c.d" IP address string into
 * an in_addr structure.  Returns 0 on failure,
 * and 1 on success.
 */
int inet_aton(const char *cp, struct in_addr *addr)
{
    if( cp==NULL || addr==NULL )
    {
        return(0);
    }

    /* Because this and INADDR_NONE are the same */
    if (strcmp(cp, "255.255.255.255") == 0)
    {
        addr->s_addr = 0xffffffff;
        return 1;
    }

    addr->s_addr = inet_addr(cp);
    return (addr->s_addr == INADDR_NONE) ? 0 : 1;
}

int inet_pton(int af, const char *src, void *dst) {
    u_int16_t ipbuf[8];
    u_int32_t val;
    u_int16_t short_val;
    char *end_ptr;
    int i,j;
    int index = 0;
    int skip_idx = -1;
    u_int16_t *dstip = (u_int16_t*)dst;

    if(!src || !dst) return -1;

    if(af == AF_INET) {
        return inet_aton(src, dst);
    }

    while(*src) {
        val = strtoul(src, &end_ptr, 16);
        if (val > USHRT_MAX)
        {
            return -1;
        }
        short_val = (u_int16_t)val;

        if(*src == ':') {
            src++;
        
            if(*src == ':') {
                if(skip_idx != -1)
                    return -1;

                skip_idx = index;

                src++;

                if(*src && *src == ':') 
                    return -1;
            }
            else if(!*src) 
                return -1;

            continue;
        }
        else if(*end_ptr == '.') {
            if(!inet_aton(src, (struct in_addr *)&ipbuf[index]))
                return -1;

            index += 2;
            
            break;
        }
        else {
            if(end_ptr == src) {
                return -1;
            }

            ipbuf[index++] = htons(short_val);

            src = end_ptr;

            /* Check for trailing garbage after the IP */
            if(index == 8 && *src) 
                return -1;
        }
    }

    if(index < 8 && skip_idx == -1)
        return -1;

    for(i = 0; i < skip_idx; i++) {
        dstip[i] = ipbuf[i];
    }

    if(skip_idx == -1) skip_idx = 0;

    for(; i < 8 - (index - skip_idx); i++) {
        dstip[i] = 0;
    }
    
    for(j = skip_idx; i < 8; i++, j++) {
        dstip[i] = ipbuf[j];
    }

    return 1;
}
