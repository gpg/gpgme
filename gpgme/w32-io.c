/* w32-io.c - W32 API I/O functions
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#ifdef HAVE_DOSISH_SYSTEM

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <windows.h>

#include "io.h"

/* 
 * We assume that a HANDLE can be represented by an int which should be true
 * for all i386 systems (HANDLE is defined as void *) and these are the only
 * systems for which Windows is available.
 * Further we assume that -1 denotes an invalid handle.
 */

#define fd_to_handle(a)  ((HANDLE)(a))
#define handle_to_fd(a)  ((int)(a))
#define pid_to_handle(a) ((HANDLE)(a))
#define handle_to_pid(a) ((pid_t)(a))


int
_gpgme_io_read ( int fd, void *buffer, size_t count )
{
    int nread = 0;
    HANDLE h = fd_to_handle (fd);

    if ( !ReadFile ( h, buffer, count, &nread, NULL) ) {
        fprintf (stderr, "** ReadFile failed: ec=%d\n", (int)GetLastError ());
        return -1;
    }

    return nread;
}


int
_gpgme_io_write ( int fd, const void *buffer, size_t count )
{
    int nwritten;
    HANDLE h = fd_to_handle (fd);

    if ( !WriteFile ( h, buffer, count, &nwritten, NULL) ) {
        fprintf (stderr, "** WriteFile failed: ec=%d\n", (int)GetLastError ());
        return -1;
    }

    return nwritten;
}

int
_gpgme_io_pipe ( int filedes[2] )
{
    HANDLE r, w;
    
    if (!CreatePipe ( &r, &w, NULL, 0))
        return -1;
    filedes[0] = handle_to_fd (r);
    filedes[1] = handle_to_fd (w);
    return 0
}

int
_gpgme_io_set_nonblocking ( int fd )
{
    return 0;
}


static char *
build_commandline ( char **argv );
{
    int i, n = 0;
    char *buf, *p;

    /* FIXME: we have to quote some things because under Windows the 
     * program parses the commandline and does some unquoting */
    for (i=0; argv[i]; i++)
        n += strlen (argv[i]) + 1;
    n += 5;                     /* "gpg " */
    buf = p = xtrymalloc (n);
    if ( !buf )
        return NULL;
    p = stpcpy (p, "gpg");
    for (i = 0; argv[i]; i++)
        p = stpcpy (stpcpy (p, " "), argv[i]);

    return buf;
}


pid_t
_gpgme_io_spawn ( const char *path, char **argv,
                  struct spawn_fd_item_s *fd_child_list,
                  struct spawn_fd_item_s *fd_parent_list )
{
    SECURITY_ATTRIBUTES sec_attr;
    PROCESS_INFORMATION pi = {
        NULL,      /* returns process handle */
        0,         /* returns primary thread handle */
        0,         /* returns pid */
        0         /* returns tid */
    };
    STARTUPINFO si = {
        0, NULL, NULL, NULL,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        NULL, NULL, NULL, NULL
    };
    char *envblock = NULL;
    int cr_flags = CREATE_DEFAULT_ERROR_MODE
                 | GetPriorityClass (GetCurrentProcess ());
    int rc;
    HANDLE save_stdout;
    HANDLE outputfd[2], statusfd[2], inputfd[2];

    sec_attr.nLength = sizeof (sec_attr);
    sec_attr.bInheritHandle = FALSE;
    sec_attr.lpSecurityDescriptor = NULL;


    arg_string = build_commandline ( argv );
    if (!arg_string )
        return -1; 

    si.cb = sizeof (si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle (STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle (STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle (STD_ERROR_HANDLE);
    if (!SetHandleInformation (si.hStdOutput,
                               HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
        fprintf (stderr, "** SHI 1 failed: ec=%d\n", (int) GetLastError ());
    }
    if (!SetHandleInformation (si.hStdError,
                               HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
        fprintf (stderr, "** SHI 2 failed: ec=%d\n", (int) GetLastError ());
    }
    

    fputs ("** CreateProcess ...\n", stderr);
    fprintf (stderr, "** args=`%s'\n", arg_string);
    fflush (stderr);
    if ( !CreateProcessA (GPG_PATH,
                          arg_string,
                          &sec_attr,     /* process security attributes */
                          &sec_attr,     /* thread security attributes */
                          TRUE,          /* inherit handles */
                          cr_flags,      /* creation flags */
                          envblock,      /* environment */
                          NULL,          /* use current drive/directory */
                          &si,           /* startup information */
                          &pi            /* returns process information */
        ) ) {
        fprintf (stderr, "** CreateProcess failed: ec=%d\n",
                 (int) GetLastError ());
        fflush (stderr);
        xfree (arg_string);
        return -1;
    }

    /* .dup_to is not used in the parent list */
    for (i=0; fd_parent_list[i].fd != -1; i++ ) {
        CloseHandle ( fd_to_handle (fd_parent_list[i].fd) );
    }

    fprintf (stderr, "** CreateProcess ready\n");
    fprintf (stderr, "**   hProcess=%p  hThread=%p\n",
             pi.hProcess, pi.hThread);
    fprintf (stderr, "**   dwProcessID=%d dwThreadId=%d\n",
             (int) pi.dwProcessId, (int) pi.dwThreadId);
    fflush (stderr);

    return handle_to_pid (pi.hProcess);
}


int
_gpgme_io_waitpid ( pid_t pid, int hang, int *r_status, int *r_signal )
{
    return 0;
}


/*
 * Select on the list of fds.
 * Returns: -1 = error
 *           0 = timeout or nothing to select
 *          >0 = number of signaled fds
 */
int
_gpgme_io_select ( struct io_select_fd_s *fds, size_t nfds )
{
    return -1;
}






#endif /*HAVE_DOSISH_SYSTEM*/









