/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2016 by Paolo Lucente
*/

/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef _UTIL_H_
#define _UTIL_H_
#endif // _UTIL_H_

/* defines */
#define ADD 0
#define SUB 1

#ifdef _WIN32
/*
#define PROT_READ   1
#define PROT_WRITE   2 
#define MAP_FAILED   (void*)-1 
#define MAP_SHARED   0x01 
#define MAP_PRIVATE   0x02
#define MAP_ANONYMOUS 0x20

#define MAX_SIZE_T	sizeof(size_t)
*/

/* MORECORE and MMAP must return MFAIL on failure */
#define MFAIL                ((void*)(MAX_SIZE_T))
#define CMFAIL               ((char*)(MFAIL)) /* defined for convenience */
#endif

#ifndef FORCEINLINE
#if defined(__GNUC__)
#define FORCEINLINE __inline __attribute__ ((always_inline))
#elif defined(_MSC_VER)
#define FORCEINLINE __forceinline
#endif
#endif
#ifndef NOINLINE
#if defined(__GNUC__)
#define NOINLINE __attribute__ ((noinline))
#elif defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE
#endif
#endif

/* prototypes */
#if (!defined __UTIL_C)
#define EXT extern
#else
#define EXT
#endif

EXT void setnonblocking(int);
EXT void setblocking(int);
EXT int daemonize();
EXT char *copy_argv(register char **);
EXT char *extract_token(char **, int);
EXT char *extract_plugin_name(char **);
EXT void trim_spaces(char *);
EXT void trim_all_spaces(char *);
EXT void strip_quotes(char *);
EXT int isblankline(char *);
EXT int iscomment(char *);
EXT int check_not_valid_char(char *, char *, int);
EXT time_t roundoff_time(time_t, char *);
EXT void write_pid_file(char *);
EXT void write_pid_file_plugin(char *, char *, char *);
EXT void remove_pid_file(char *);
EXT int sanitize_buf_net(char *, char *, int);
EXT int sanitize_buf(char *);
EXT void mark_columns(char *);
EXT int Setsocksize(int, int, int, void *, int);
EXT int getCPUs();
EXT void *map_shared(void *, size_t, int, int, int, off_t);
EXT void lower_string(char *);
EXT int file_lock(int);
EXT int file_unlock(int);
EXT void strftime_same(char *, int, char *, const time_t *);
EXT void stick_bosbit(u_char *);
EXT int check_bosbit(u_char *);
EXT u_int32_t decode_mpls_label(char *);
EXT int timeval_cmp(struct timeval *, struct timeval *);
#if defined _WIN32
EXT HANDLE open_output_file(char *, char *, int);
#else
EXT FILE *open_output_file(char *, char *, int);
#endif
//EXT void link_latest_output_file(char *, char *);
EXT void close_output_file(FILE *);
EXT void escape_ip_uscores(char *);
EXT int mkdir_multilevel(const char *, int, uid_t, gid_t);
EXT char bin_to_hex(int);
EXT int print_hex(const u_char *, u_char *, int);
EXT void write_pid_file(char *);
EXT void hash_init_key(pm_hash_key_t *);
EXT int hash_init_serial(pm_hash_serial_t *, u_int16_t);
EXT int hash_alloc_key(pm_hash_key_t *, u_int16_t);
EXT int hash_dup_key(pm_hash_key_t *, pm_hash_key_t *);
EXT void hash_destroy_key(pm_hash_key_t *);
EXT void hash_destroy_serial(pm_hash_serial_t *);
EXT void hash_serial_set_off(pm_hash_serial_t *, u_int16_t);
EXT pm_hash_key_t *hash_serial_get_key(pm_hash_serial_t *);
EXT u_int16_t hash_serial_get_off(pm_hash_serial_t *);
EXT u_int16_t hash_key_get_len(pm_hash_key_t *);
EXT char *hash_key_get_val(pm_hash_key_t *);
EXT int hash_key_cmp(pm_hash_key_t *, pm_hash_key_t *);
EXT u_int64_t getTimeMSec();
EXT u_int64_t timeMSecDiff(struct timespec *, struct timespec *);
//EXT size_t curl_writefunc(void *, size_t, size_t, void *);
//EXT bool postHTTPJsonData(char *, char *, char *, char *, CURL *);

EXT void replace_string(char *, int, char *, char *);
#undef EXT
