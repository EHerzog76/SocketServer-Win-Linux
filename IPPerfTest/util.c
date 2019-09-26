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

#define __UTIL_C

/* includes */
#include "IPPerfTest.h"
#ifndef _WIN32
#include <search.h>
#else
#include <c:\Program Files (x86)\Windows Kits\8.1\Include\um\WinSock2.h>
#include <windows.h>
#endif // !_WIN32
#include "util.h"

/* functions */
void setnonblocking(int sock)
{
#ifndef _WIN32	/*  defined(unix) || defined(__unix__) || defined(__MACH__)  */
	/*
	* fcntl may set:
	*
	* EACCES, EAGAIN: Operation is prohibited by locks held by other
	*          processes. Or, operation is prohibited because the file has
	*          been memory-mapped by another process.
	* EBADF:   fd is not an open file descriptor, or the command was F_SETLK
	*          or F_SETLKW and the file descriptor open mode doesn't match
	*          with the type of lock requested.
	* EDEADLK: It was detected that the specified F_SETLKW command would
	*          cause a deadlock.
	* EFAULT:  lock is outside your accessible address space.
	* EINTR:   For F_SETLKW, the command was interrupted by a signal. For
	*          F_GETLK and F_SETLK, the command was interrupted by a signal
	*          before the lock was checked or acquired. Most likely when
	*          locking a remote file (e.g. locking over NFS), but can
	*          sometimes happen locally.
	* EINVAL:  For F_DUPFD, arg is negative or is greater than the maximum
	*          allowable value. For F_SETSIG, arg is not an allowable signal
	*          number.
	* EMFILE:  For F_DUPFD, the process already has the maximum number of
	*          file descriptors open.
	* ENOLCK:  Too many segment locks open, lock table is full, or a remote
	*          locking protocol failed (e.g. locking over NFS).
	* EPERM:   Attempted to clear the O_APPEND flag on a file that has the
	*          append-only attribute set.
	*/
	int opts;

	opts = fcntl(sock, F_GETFL);
	if (opts < 0)
	{
		//perror("fcntl(F_GETFL)");
		return; // return -1;
	}

	opts |= O_NONBLOCK;
	if (fcntl(sock, F_SETFL, opts) < 0)
	{
		//perror("fcntl(F_SETFL)");
		return; // return -1;
	}
#else /* _WIN32 */
	u_int ul = 1;
	//return ioctlsocket(sock, FIONBIO, &ul);
	ioctlsocket(sock, FIONBIO, &ul);
#endif /* _WIN32 */
	return;	// return opts;
}

void setblocking(int sock)
{
#ifdef _WIN32
	u_int ul = 0;
	ioctlsocket(sock, FIONBIO, &ul);
#else

  int opts;

  opts = fcntl(sock, F_GETFL);
  opts & O_NONBLOCK ? opts ^= O_NONBLOCK : opts;
  fcntl(sock, F_SETFL, opts);
#endif
}

int daemonize()
{
#ifndef _WIN32
	int fdd;
	pid_t pid;

	pid = fork();

	switch (pid) {
	case -1:
		return -1;
	case 0:
		break;
	default:
		exit(0);
	}

	if (setsid() == -1) return -1;

	fdd = open("/dev/null", O_RDWR, 0);
	if (fdd != -1) {
		dup2(fdd, 0);
		dup2(fdd, 1);
		dup2(fdd, 2);
		if (fdd > 2) close(fdd);
	}
#else
	printf("Under Windows run it as service.\nUse /i for service-installation.\n\n");
#endif // !_WIN32

  return 0;
}

char *extract_token(char **string, int delim)
{
  char *token, *delim_ptr;

  if (!strlen(*string)) return NULL;

  start:
  if (delim_ptr = strchr(*string, delim)) {
    *delim_ptr = '\0';
    token = *string;
    *string = delim_ptr+1;
    if (!strlen(token)) goto start;
  }
  else {
    token = *string;
    *string += strlen(*string);
    if (!strlen(token)) return NULL;
  }

  return token;
}

char *extract_plugin_name(char **string)
{
  char *name, *delim_ptr;
  char name_start = '[';
  char name_end = ']';

  if ((delim_ptr = strchr(*string, name_start))) {
    *delim_ptr = '\0';
    name = delim_ptr+1;
    if ((delim_ptr = strchr(name, name_end))) *delim_ptr = '\0';
    else {
      printf("ERROR: Not weighted parhentesis: '[%s'\n", name);
      exit(1);
    }
  }
  else return NULL;

  return name;
}


/*
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

char *copy_argv(register char **argv)
{
  register char **p;
  register unsigned int len = 0;
  char *buf;
  char *src, *dst;

  p = argv;
  if (*p == 0)
    return NULL;

  while (*p)
    len += strlen(*p++) + 1;

   buf = (char *)malloc(len);
   if (buf == NULL) {
     printf("ERROR: copy_argv: malloc()\n");
     return NULL;
   }

   p = argv;
   dst = buf;
   while ((src = *p++) != NULL) {
     while ((*dst++ = *src++) != '\0');
     dst[-1] = ' ';
   }

   dst[-1] = '\0';
   return buf;
}

void trim_spaces(char *buf)
{
  char *tmp_buf;
  int i, len;

  len = strlen(buf);

  tmp_buf = (char *)malloc(len + 1);
  if (tmp_buf == NULL) {
	  printf("ERROR: trim_spaces: malloc() failed.\n");
    return;
  }

  /* trimming spaces at beginning of the string */
  for (i = 0; i <= len; i++) {
    if (!isspace(buf[i])) {
      if (i != 0) {
        strlcpy(tmp_buf, &buf[i], len+1-i);
        strlcpy(buf, tmp_buf, len+1-i);
      }
      break;
    }
  }

  /* trimming spaces at the end of the string */
  for (i = strlen(buf)-1; i >= 0; i--) {
    if (isspace(buf[i]))
      buf[i] = '\0';
    else break;
  }

  free(tmp_buf);
}

void trim_all_spaces(char *buf)
{
  char *tmp_buf;
  int i = 0, len, quotes = FALSE;

  len = strlen(buf);

  tmp_buf = (char *)malloc(len + 1);
  if (tmp_buf == NULL) {
	  printf("ERROR: trim_all_spaces: malloc() failed.\n");
    return;
  }

  /* trimming all spaces */
  while (i <= len) {
    if (buf[i] == '\'') {
      if (!quotes) quotes = TRUE;
      else if (quotes) quotes = FALSE;
    }
    if (isspace(buf[i]) && !quotes) {
      strlcpy(tmp_buf, &buf[i+1], len);
      strlcpy(&buf[i], tmp_buf, len);
      len--;
    }
    else i++;
  }

  free(tmp_buf);
}

void strip_quotes(char *buf)
{
  char *ptr, *tmp_buf;
  int i = 0, len;

  len = strlen(buf);

  tmp_buf = (char *) malloc(len + 1);
  if (tmp_buf == NULL) {
	  printf("ERROR: strip_quotes: malloc() failed.\n");
    return;
  }
  ptr = buf;

  /* stripping all quote marks using a temporary buffer to avoid string corruption by strcpy() */
  while (i <= len) {
    if (ptr[i] == '\'') {
      strcpy(tmp_buf, &ptr[i+1]);
      strcpy(&buf[i], tmp_buf);
      len--;
    }
    else i++;
  }

  free(tmp_buf);
}

int isblankline(char *line)
{
  int len, j, n_spaces = 0;

  if (!line) return FALSE;

  len = strlen(line);
  for (j = 0; j < len; j++)
    if (isspace(line[j])) n_spaces++;

  if (n_spaces == len) return TRUE;
  else return FALSE;
}

int iscomment(char *line)
{
  int len, j, first_char = TRUE;

  if (!line) return FALSE;

  len = strlen(line);
  for (j = 0; j <= len; j++) {
    if (!isspace(line[j])) first_char--;
    if (!first_char) {
      if (line[j] == '!' || line[j] == '#') return TRUE;
      else return FALSE;
    }
  }

  return FALSE;
}

time_t roundoff_time(time_t t, char *value)
{
  // char *value = config.sql_history_roundoff;
  struct tm *rounded;
  int len, j;

  rounded = localtime(&t);
  rounded->tm_sec = 0; /* default round off */

  if (value) {
    len = strlen(value);
    for (j = 0; j < len; j++) {
      if (value[j] == 'm') rounded->tm_min = 0;
      else if (value[j] == 'h') {
	rounded->tm_min = 0;
	rounded->tm_hour = 0;
      }
      else if (value[j] == 'd') {
        rounded->tm_min = 0;
        rounded->tm_hour = 0;
	rounded->tm_mday = 1;
      }
      else if (value[j] == 'w') {
        rounded->tm_min = 0;
        rounded->tm_hour = 0;
	while (rounded->tm_wday > 1) {
	  rounded->tm_mday--;
	  rounded->tm_wday--;
	}
      }
      else if (value[j] == 'M') {
        rounded->tm_min = 0;
        rounded->tm_hour = 0;
	rounded->tm_mday = 1;
	rounded->tm_mon = 0;
      }
      else printf("WARN: ignoring unknown round off value: %c\n", value[j]);
    }
  }

  t = mktime(rounded);
  return t;
}

/* op = 0 (add); op = 1 (sub) */
time_t calc_monthly_timeslot(time_t t, int howmany, int op)
{
  time_t base = t, final;
  struct tm *tmt;

  tmt = localtime(&t);

  while (howmany) {
    tmt->tm_mday = 1;
    if (op == ADD) tmt->tm_mon++;
    else if (op == SUB) tmt->tm_mon--;
    howmany--;
  }

  final = mktime(tmt);

  return (final-base);
}

#if defined _WIN32
HANDLE open_output_file(char *filename, char *mode, int lock)
{
	HANDLE file;
	// file and path, change accordingly. LPCWSTR is a pointer to a constant
	// null-terminated string of 16-bit Unicode characters. It is a typedef:
	// typedef CONST WCHAR *LPCWSTR. The modifier 'L' is for wide character.
	//unsigned long lpdwFlags[100];
	int ret;

	if (!filename || !mode) return NULL;

	ret = mkdir_multilevel(filename, TRUE, 0, 0);
	if (ret) {
		printf("ERROR: [%s] open_output_file(): mkdir_multilevel() failed.\n", filename);
		return file;
	}

	/*
	TCHAR szFilename[MAX_PATH];
	if (sizeof(TCHAR) > 1) {
		ret = MultiByteToWideChar(CP_ACP, 0, filename, -1, szFilename, MAX_PATH);
	}
	else
		*szFilename = filename;
	*/
	// Create a file with the given information...
	if(lock)
		file = CreateFileA(filename, // file to be opened
			GENERIC_WRITE,		// open for writing
			FILE_SHARE_READ,	// exclusive writing
			NULL,				// default security
			OPEN_ALWAYS,		// create new file only     CREATE_ALWAYS, OPEN_ALWAYS, OPEN_EXISTING
			FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE, // | FILE_FLAG_NO_BUFFERING  normal file archive   impersonate client: SECURITY_IMPERSONATION
			NULL); // no attr. template
	else
		file = CreateFileA(filename, // file to be opened
			GENERIC_WRITE,		// open for writing
			FILE_SHARE_WRITE | FILE_SHARE_READ,	// share for writing
			NULL,				// default security
			OPEN_ALWAYS,		// create new file only     CREATE_ALWAYS, OPEN_ALWAYS, OPEN_EXISTING
			FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE, // | FILE_FLAG_NO_BUFFERING  normal file archive		impersonate client: SECURITY_IMPERSONATION
			NULL); // no attr. template

	if (file == INVALID_HANDLE_VALUE)
	{
		//printf("Could not open %s file, error %d\n", fname, GetLastError());
		printf("ERROR: [%s] open_output_file(): mkdir_multilevel() failed (errorno: %d).\n", filename, GetLastError());
		file = NULL;
	}
	else
	{
		//printf("File's HANDLE is OK!\n");
		//ret = GetHandleInformation(File, lpdwFlags);
		//printf("The return value is %d, error %d\n", ret, GetLastError());

		/* if (lock) {
			LockFileEx(file, LOCKFILE_FAIL_IMMEDIATELY, 0, 0, 0, NULL);
			Log(LOG_ERR, "ERROR ( %s/%s ): [%s] open_output_file(): file_lock() failed.\n", config.name, config.type, filename);
		} */
	}
	return(file);
}
#else
FILE *open_output_file(char *filename, char *mode, int lock)
{
	FILE *file = NULL;
	uid_t owner = -1;
	gid_t group = -1;
	int ret;

	if (!filename || !mode) return file;

	if (config.files_uid) owner = config.files_uid;
	if (config.files_gid) group = config.files_gid;

	ret = mkdir_multilevel(filename, TRUE, owner, group);
	if (ret) {
		Log(LOG_ERR, "ERROR ( %s/%s ): [%s] open_output_file(): mkdir_multilevel() failed.\n", config.name, config.type, filename);
		return file;
	}

	ret = access(filename, F_OK);

	file = fopen(filename, mode);

	if (file) {
		if (chown(filename, owner, group) == -1)
			Log(LOG_WARNING, "WARN ( %s/%s ): [%s] open_output_file(): chown() failed (%s).\n", config.name, config.type, filename, strerror(errno));

		if (lock) {
			if (file_lock(fileno(file))) {
				Log(LOG_ERR, "ERROR ( %s/%s ): [%s] open_output_file(): file_lock() failed.\n", config.name, config.type, filename);
				file = NULL;
			}
		}
	}
	else {
		Log(LOG_WARNING, "WARN ( %s/%s ): [%s] open_output_file(): fopen() failed (%s).\n", config.name, config.type, filename, strerror(errno));
		file = NULL;
	}

	return file;
}
#endif

/*
void link_latest_output_file(char *link_filename, char *filename_to_link)
{
  int ret, rewrite_latest = FALSE;
  char buf[SRVBUFLEN];
  uid_t owner = -1;
  gid_t group = -1;

  if (!link_filename || !filename_to_link) return;

#ifndef _WIN32
  if (config.files_uid) owner = config.files_uid;
  if (config.files_gid) group = config.files_gid;
#endif // !_WIN32

  // create dir structure to get to file, if needed
  ret = mkdir_multilevel(link_filename, TRUE, owner, group);
  if (ret) {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] link_latest_output_file(): mkdir_multilevel() failed.\n", config.name, config.type, buf);
    return;
  }

#ifndef _WIN32
  ret = access(link_filename, F_OK);
  if (!ret) {
	  struct stat s1, s2;

	  memset(&s1, 0, sizeof(struct stat));
	  memset(&s2, 0, sizeof(struct stat));
	  readlink(link_filename, buf, SRVBUFLEN);

	  // filename_to_link is newer than buf or buf is un-existing
	  stat(buf, &s1);
	  stat(filename_to_link, &s2);
	  if (s2.st_mtime >= s1.st_mtime) rewrite_latest = TRUE;
  }
#else
  FILETIME ftCreate1, ftAccess1, ftWrite1, ftCreate2, ftAccess2, ftWrite2;

  HANDLE hFile1 = CreateFile(link_filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  HANDLE hFile2 = CreateFile(filename_to_link, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  if (hFile2) {
	  ret = GetFileTime(hFile2, &ftCreate2, &ftAccess2, &ftWrite2);
	  if (ret) {
		  // Convert the last-write time to local time.
		  //FileTimeToSystemTime(&ftWrite, &stUTC);
		  //SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

		  ret = GetFileTime(hFile1, &ftCreate1, &ftAccess1, &ftWrite1);
		  if (ret) {
			  if (ftWrite2.dwHighDateTime >= ftWrite1.dwHighDateTime)
				  if (ftWrite2.dwLowDateTime >= ftWrite1.dwLowDateTime) rewrite_latest = TRUE;
		  }
		  else
		  {
			  rewrite_latest = TRUE;
		  }
	  }
	  CloseHandle(hFile2);
	  CloseHandle(hFile1);
  }
#endif // !_WIN32
  else rewrite_latest = TRUE;

  if (rewrite_latest) {
#if defined _WIN32
	  DeleteFile(link_filename);
	  // if a file with same name exists let's investigate if filename_to_link is newer
	  CreateSymbolicLink(
		  link_filename,	//SymlinkFileName
		  filename_to_link,	//Target Filename
		  0);
#else
    unlink(link_filename);
    symlink(filename_to_link, link_filename);
	if (lchown(link_filename, owner, group) == -1)
		Log(LOG_WARNING, "WARN ( %s/%s ): link_latest_output_file(): unable to chown() '%s'.\n", config.name, config.type, link_filename);
#endif
  }
}
*/

#if defined _WIN32
void close_output_file(HANDLE f)
#else
void close_output_file(FILE *f)
#endif
{
#if defined _WIN32
	if (f) CloseHandle(f);
#else
	if (f) fclose(f);
#endif // _WIN32
}

void escape_ip_uscores(char *str)
{
  int idx, len = 0;

  if (str) len = strlen(str);
  for (idx = 0; idx < len; idx++) {
    if (str[idx] == '.' || str[idx] == ':') str[idx] = '_';
  }
}

int mkdir_multilevel(const char *path, int trailing_filename, uid_t owner, gid_t group)
{
	char opath[SRVBUFLEN];
	char *p;
	int ret = 0, len = 0;

	strlcpy(opath, path, sizeof(opath));

	for (p = opath; *p; p++, len++) {
		if (*p == '/') {
			*p = '\0';
#if defined _WIN32
			ret = CreateDirectory(opath, NULL);
			if (ret) return ret;
#else
			if (len && access(opath, F_OK)) {
				ret = mkdir(opath, (S_IRWXU | S_IRWXG | S_IRWXO));
				if (ret) return ret;
				if (chown(opath, owner, group) == -1) return ret;
			}
#endif
			*p = '/';
		}
	}

	/* do a last mkdir in case the path was not terminated
	   by a traiing '/' and we do not expect the last part
	   to be a filename, ie. trailing_filename set to 0 */
#if defined _WIN32
	if (!trailing_filename) {
		ret = CreateDirectory(opath, NULL);
		if (ret) return ret;
	}
#else
	if (!trailing_filename && access(opath, F_OK)) {
		ret = mkdir(opath, (S_IRWXU | S_IRWXG | S_IRWXO));
		if (ret) return ret;
	}
#endif
	return ret;
}

char bin_to_hex(int nib) { return (nib < 10) ? ('0' + nib) : ('A' - 10 + nib); }

int print_hex(const u_char *a, u_char *buf, int len)
{
	int b = 0, i = 0;

	for (; i < len; i++) {
		u_char byte;

		// if (a[i] == '\0') break;

		byte = a[i];
		buf[b++] = bin_to_hex(byte >> 4);
		buf[b++] = bin_to_hex(byte & 0x0f);

		// separate the bytes with a dash
		if (i < (len - 1)) buf[b++] = '-';
	}

	if (buf[b - 1] == '-') {
		buf[b - 1] = '\0';
		return b;
	}
	else {
		buf[b] = '\0';
		return (b + 1);
	}
}

void write_pid_file(char *filename)
{
  FILE *file;
  char pid[10];
  uid_t owner = -1;
  gid_t group = -1;

  unlink(filename);

  //if (config.files_uid) owner = config.files_uid;
  //if (config.files_gid) group = config.files_gid;
#if !defined(_WIN32)
  file = fopen(filename,"w");
  if (file) {
    if (chown(filename, owner, group) == -1)
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Unable to chown(): %s\n", config.name, config.type, filename, strerror(errno));

    if (file_lock(fileno(file))) {
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Unable to obtain lock.\n", config.name, config.type, filename);
      return;
    }
    sprintf(pid, "%d\n", getpid());
    fwrite(pid, strlen(pid), 1, file);

    file_unlock(fileno(file));
	fclose(file);
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] fopen() failed.\n", config.name, config.type, filename);
    return;
  }
#endif
}

void write_pid_file_plugin(char *filename, char *type, char *name)
{
  int len = strlen(filename) + strlen(type) + strlen(name) + 3;
  FILE *file;
  char *fname, pid[10], minus[] = "-";
  uid_t owner = -1;
  gid_t group = -1;
#if !defined(_WIN32)
  fname = malloc(len);
  if (!fname) {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] malloc() failed.\n", config.name, config.type, filename);
    return;
  }
  memset(fname, 0, len);
  strcpy(fname, filename);
  strcat(fname, minus);
  strcat(fname, type);
  strcat(fname, minus);
  strcat(fname, name);

  config.pidfile = fname;
  unlink(fname);

  if (config.files_uid) owner = config.files_uid;
  if (config.files_gid) group = config.files_gid;

  file = fopen(fname, "w");
  if (file) {
    if (chown(fname, owner, group) == -1)
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Unable to chown(): %s\n", config.name, config.type, fname, strerror(errno));

    if (file_lock(fileno(file))) {
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Unable to obtain lock.\n", config.name, config.type, fname);
      goto exit_lane;
    }
    sprintf(pid, "%d\n", getpid());
    fwrite(pid, strlen(pid), 1, file);

    file_unlock(fileno(file));
    fclose(file);
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] fopen() failed.\n", config.name, config.type, fname);
    goto exit_lane;
  }

  exit_lane:
  free(fname);
#endif
}

void remove_pid_file(char *filename)
{
#ifndef _WIN32
	unlink(filename);
#endif // !_WIN32
}

int file_lock(int fd)
{
  int ret;
#if defined SOLARIS
  flock_t lock;

  lock.l_type = F_WRLCK;
  lock.l_whence = 0;
  lock.l_start = 0;
  lock.l_len = 0;

  ret = fcntl(fd, F_SETLK, &lock);
  return((ret == -1) ? -1 : 0);
#elif !defined(_WIN32)
  ret = flock(fd, LOCK_EX);
  return ret;
#else

#endif
}

int file_unlock(int fd)
{
  int ret;
#if defined SOLARIS
  flock_t lock;

  lock.l_type = F_UNLCK;
  lock.l_whence = 0;
  lock.l_start = 0;
  lock.l_len = 0;

  ret = fcntl(fd, F_SETLK, &lock);
  return((ret == -1) ? -1 : 0);
#elif !defined(_WIN32)
  ret = flock(fd, LOCK_UN);
  return ret;
#else

#endif
}

int sanitize_buf_net(char *filename, char *buf, int rows)
{
  if (!sanitize_buf(buf)) {
    if (!strchr(buf, '/')) {
      printf("ERROR: [%s:%u] Missing '/' separator. Ignoring.\n", filename, rows);
      return TRUE;
    }
  }
  else return TRUE;

  return FALSE;
}

int sanitize_buf(char *buf)
{
  int x = 0, valid_char = 0;

  trim_all_spaces(buf);
  while (x < strlen(buf)) {
    if (!isspace(buf[x])) valid_char++;
    x++;
  }
  if (!valid_char) return TRUE;
  if (buf[0] == '!') return TRUE;

  return FALSE;
}

int check_not_valid_char(char *filename, char *buf, int c)
{
  if (!buf) return FALSE;

  if (strchr(buf, c)) {
	  printf("ERROR: [%s] Invalid symbol '%c' detected.\n", filename, c);
    return TRUE;
  }
  else return FALSE;
}

void mark_columns(char *buf)
{
  int len, x, word = FALSE, quotes = FALSE;

  if (!buf) return;

  len = strlen(buf);
  for (x = 0; x < len; x++) {
    if (buf[x] == '\'') {
      if (!quotes) quotes = TRUE;
      else if (quotes) quotes = FALSE;
    }
    if ((isalpha(buf[x])||isdigit(buf[x])||ispunct(buf[x])) && !word) word = TRUE;
    if (isspace(buf[x]) && word && !quotes) {
      buf[x] = '|';
      word = FALSE;
    }
  }

  /* removing trailing '|' if any */
  x = strlen(buf);
  word = FALSE;

  while (x > 0) {
    if (buf[x] == '|' && !word) buf[x] = '\0';
    if ((isalpha(buf[x])||isdigit(buf[x])||ispunct(buf[x])) && !word) word = TRUE;
    x--;
  }
}

int Setsocksize(int s, int level, int optname, void *optval, int optlen)
{
  int ret, len = sizeof(int), saved, value;

  memcpy(&value, optval, sizeof(int));

  getsockopt(s, level, optname, &saved, &len);
  if (value > saved) {
    for (; value; value >>= 1) {
      ret = setsockopt(s, level, optname, &value, optlen);
      if (ret >= 0) break;
    }
    if (!value) setsockopt(s, level, optname, &saved, len);
  }

  return ret;
}

int getCPUs() {
	int NrOfCPUs = 0;
#ifdef _WIN32
	SYSTEM_INFO	SystemInfo;

	//Determine how many processors are on the system.
	GetSystemInfo(&SystemInfo);

	NrOfCPUs = SystemInfo.dwNumberOfProcessors;
#else
	//DoTo...
#endif
	return(NrOfCPUs);
}

#ifdef _WIN32
#ifdef __cplusplus
extern "C" {
#ifndef FORCEINLINE
#define FORCEINLINE inline
#endif
#endif /* __cplusplus */
#ifndef FORCEINLINE
#define FORCEINLINE
#endif

/* Win32 MMAP via VirtualAlloc */
static FORCEINLINE void* win32mmap(size_t size) {
#ifdef USE_COW
		void* ptr = AllocHeapBlock(size, FALSE);
#else
		void* ptr = VirtualAlloc(0, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#endif
		return (ptr != 0) ? ptr : MFAIL;
	}

	/* For direct MMAP, use MEM_TOP_DOWN to minimize interference */
	static FORCEINLINE void* win32direct_mmap(size_t size) {
#ifdef USE_COW
		void* ptr = AllocHeapBlock(size, TRUE);
#else
		void* ptr = VirtualAlloc(0, size, MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE);
#endif
		return (ptr != 0) ? ptr : MFAIL;
	}

	/* This function supports releasing coalesced segments */
	static FORCEINLINE int win32munmap(void* ptr, size_t size) {
#ifdef USE_COW
		if (FreeHeapBlock(ptr, size) == FALSE)
#else
		if (VirtualFree(ptr, 0, MEM_RELEASE) == FALSE)
#endif
		{
			return -1;
		}
		return 0;
	}
#endif

void *map_shared(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
#if defined(_WIN32)
	return win32mmap(len);
#elif defined USE_DEVZERO
  void *mem;
  int devzero;

  devzero = open ("/dev/zero", O_RDWR);
  if (devzero < 0) return MAP_FAILED;
  mem = mmap(addr, len, prot, flags, devzero, off);
  close(devzero);

  return mem;
#else /* MAP_ANON or MAP_ANONYMOUS */
  return (void *)mmap(addr, len, prot, flags, fd, off);
#endif
}

void lower_string(char *string)
{
  int i = 0;

  if (!string) return;

  while (string[i] != '\0') {
    string[i] = tolower(string[i]);
    i++;
  }
}

void strftime_same(char *s, int max, char *tmp, const time_t *now)
{
  struct tm *nowtm;

  nowtm = localtime(now);
  strftime(tmp, max, s, nowtm);
  strlcpy(s, tmp, max);
}


void stick_bosbit(u_char *label)
{
  u_char *ptr;

  ptr = label+2;
  *ptr |= 0x1;
}

int check_bosbit(u_char *label)
{
  u_char *ptr;

  ptr = label+2;

  if (*ptr & 0x1) return TRUE;
  else return FALSE;
}

u_int32_t decode_mpls_label(char *label)
{
  u_int32_t ret = 0;
  u_char label_ttl[4];

  memset(label_ttl, 0, 4);
  memcpy(label_ttl, label, 3);
  ret = ntohl(*(u_int32_t *)(label_ttl));
  ret = ((ret & 0xfffff000 /* label mask */) >> 12 /* label shift */);

  return ret;
}

/*
 * timeval_cmp(): returns > 0 if a > b; < 0 if a < b; 0 if a == b.
 */
int timeval_cmp(struct timeval *a, struct timeval *b)
{
  if (a->tv_sec > b->tv_sec) return 1;
  if (a->tv_sec < b->tv_sec) return -1;
  if (a->tv_sec == b->tv_sec) {
    if (a->tv_usec > b->tv_usec) return 1;
    if (a->tv_usec < b->tv_usec) return -1;
    if (a->tv_usec == b->tv_usec) return 0;
  }
}

void replace_string(char *str, int string_len, char *var, char *value)
{
  char *ptr_start, *ptr_end;
  char *buf = NULL;
  int ptr_len, len;

  if (!str || !var || !value) return;

  if (!strchr(str, '$')) return;

  if (string_len < ((strlen(str) + strlen(value)) - strlen(var))) return;

  buf = malloc(sizeof(char) * string_len);
  ptr_start = strstr(str, var);
  if (ptr_start) {
    len = strlen(ptr_start);
    ptr_end = ptr_start;
    ptr_len = strlen(var);
    ptr_end += ptr_len;
    len -= ptr_len;

    snprintf(buf, string_len, "%s", value);
    strncat(buf, ptr_end, len);

    len = strlen(buf);
    *ptr_start = '\0';
    strncat(str, buf, len);
  }
  free(buf);
}

void set_truefalse_nonzero(int *value)
{
  if (!value) return;

  if (!(*value)) (*value) = TRUE;
  else if ((*value) == FALSE_NONZERO) (*value) = FALSE;
}

void hash_init_key(pm_hash_key_t *key)
{
  if (!key) return;

  memset(key->val, 0, key->len);
}

int hash_alloc_key(pm_hash_key_t *key, u_int16_t key_len)
{
  if (!key || !key_len) return ERR;

  if (!key->val) {
    key->val = malloc(key_len);
    if (key->val) {
      key->len = key_len;
      hash_init_key(key);
    }
    else return ERR;
  }
  else {
    key->val = realloc(key->val, key_len);
    if (key->val) key->len = key_len;
    else return ERR;
  }

  return SUCCESS;
}

int hash_dup_key(pm_hash_key_t *dst, pm_hash_key_t *src)
{
  if (!src || !dst) return ERR;

  if (hash_alloc_key(dst, src->len) == ERR) return ERR;

  memcpy(dst->val, src->val, src->len);

  return SUCCESS;
}

void hash_destroy_key(pm_hash_key_t *key)
{
  if (!key) return;

  free(key->val);
  memset(key, 0, sizeof(pm_hash_key_t));
}

int hash_init_serial(pm_hash_serial_t *serial, u_int16_t key_len)
{
  int ret;

  if (!serial || !key_len) return ERR;

  memset(serial, 0, sizeof(pm_hash_serial_t));
  return hash_alloc_key(&serial->key, key_len);
}

void hash_destroy_serial(pm_hash_serial_t *serial)
{
  if (!serial) return;

  hash_destroy_key(&serial->key);
  memset(serial, 0, sizeof(pm_hash_serial_t));
}

void hash_serial_set_off(pm_hash_serial_t *serial, u_int16_t off)
{
  if (!serial) return;

  serial->off = off;
}

u_int16_t hash_serial_get_off(pm_hash_serial_t *serial)
{
  if (!serial) return ERR;

  return serial->off;
}

pm_hash_key_t *hash_serial_get_key(pm_hash_serial_t *serial)
{
  if (!serial) return NULL;

  return &serial->key;
}

u_int16_t hash_key_get_len(pm_hash_key_t *key)
{
  if (!key) return ERR;

  return key->len;
}

char *hash_key_get_val(pm_hash_key_t *key)
{
  if (!key) return NULL;

  return key->val;
}

void hash_serial_append(pm_hash_serial_t *serial, char *val, u_int16_t len, int realloc)
{
  u_int16_t key_len, key_off, rem_len;
  int ret;

  if (!serial || !val || !len) return;

  key_len = hash_key_get_len(&serial->key);
  key_off = hash_serial_get_off(serial);
  rem_len = (key_len - key_off);

  if (len > rem_len) {
    if (!realloc) return;
    else {
      ret = hash_alloc_key(&serial->key, (hash_key_get_len(&serial->key) + (len - rem_len)));
      if (ret == ERR) return;
    }
  }

  memcpy((hash_key_get_val(&serial->key) + key_off), val, len);
  hash_serial_set_off(serial, (key_off + len));
}

int hash_key_cmp(pm_hash_key_t *a, pm_hash_key_t *b)
{
  if (a->len != b->len) return (a->len - b->len);

  return memcmp(a->val, b->val, b->len);
}

u_int64_t getTimeMSec() {
#ifdef _WIN32
	//FILETIME ft;
	//u_int64_t time1;
	//GetSystemTimeAsFileTime(&ft);
	//return((((ULONGLONG)ft.dwHighDateTime) << 32) + ft.dwLowDateTime);

	LARGE_INTEGER s_frequency;
	BOOL s_use_qpc = QueryPerformanceFrequency(&s_frequency);
	if (s_use_qpc) {
		LARGE_INTEGER now;
		QueryPerformanceCounter(&now);
		return (1000000LL * now.QuadPart) / s_frequency.QuadPart;
	}
	else {
		return (u_int64_t)GetTickCount();
	}

	//SYSTEMTIME t;
	//GetLocalTime(&t);
	//t.wHour *3600000 + t.wMinute *60000 + t.wSecond *1000 + t.wMilliseconds;
#else
	struct timeval time;
	gettimeofday(&time, NULL);

	//return (u_int64_t)time.tv_sec * 1000L + time.tv_usec /1000;	//millisec.
	return (u_int64_t)time.tv_sec * 1000000L + time.tv_usec;		//microsec.
#endif
}

u_int64_t timeMSecDiff(struct timespec *timeA_p, struct timespec *timeB_p)
{
	return ((timeA_p->tv_sec * 1000000000) + timeA_p->tv_nsec) -
		((timeB_p->tv_sec * 1000000000) + timeB_p->tv_nsec);
}
