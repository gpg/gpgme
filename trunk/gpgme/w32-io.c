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

#include "util.h"
#include "io.h"

#define DEBUG_SELECT_ENABLED 1

#if DEBUG_SELECT_ENABLED
# define DEBUG_SELECT(a) fprintf a
#else
# define DEBUG_SELECT(a) do { } while(0)
#endif



/* 
 * We assume that a HANDLE can be represented by an int which should be true
 * for all i386 systems (HANDLE is defined as void *) and these are the only
 * systems for which Windows is available.
 * Further we assume that -1 denotes an invalid handle.
 */

#define fd_to_handle(a)  ((HANDLE)(a))
#define handle_to_fd(a)  ((int)(a))
#define pid_to_handle(a) ((HANDLE)(a))
#define handle_to_pid(a) ((int)(a))


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
    return 0;
}

int
_gpgme_io_close ( int fd )
{
    if ( fd == -1 )
        return -1;
    return CloseHandle (fd_to_handle(fd)) ? 0 : -1;
}


int
_gpgme_io_set_nonblocking ( int fd )
{
    return 0;
}


static char *
build_commandline ( char **argv )
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


int
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
    int i, rc;
    char *arg_string;
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
_gpgme_io_waitpid ( int pid, int hang, int *r_status, int *r_signal )
{
    HANDLE proc = fd_to_handle (pid);
    int code, exc, ret = 0;

    *r_status = 0;
    *r_signal = 0;
    code = WaitForSingleObject ( proc, hang? INFINITE : NULL );
    switch (code) {
      case WAIT_FAILED:
        fprintf (stderr, "** WFSO pid=%d failed: %d\n",
                 (int)pid, (int)GetLastError () );
        break;

      case WAIT_OBJECT_0:
        if (!GetExitCodeProcess (proc, &exc)) {
            fprintf (stderr, "** GECP pid=%d failed: ec=%d\n",
                     (int)pid, (int)GetLastError () );
            *r_status = 4; 
        }
        else {
            fprintf (stderr, "** GECP pid=%d exit code=%d\n",
                        (int)pid,  exc);
            *r_status = exc;
        }
        ret = 1;
        break;

      case WAIT_TIMEOUT:
        fprintf (stderr, "** WFSO pid=%d timed out\n", (int)pid);
        break;

      default:
        fprintf (stderr, "** WFSO pid=%d returned %d\n", (int)pid, code );
        break;
    }
    return ret;
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
    HANDLE waitbuf[MAXIMUM_WAIT_OBJECTS];
    int code, nwait;
    int i, any, ret;

    DEBUG_SELECT ((stderr, "gpgme:select on [ "));
    any = 0;
    nwait = 0;
    for ( i=0; i < nfds; i++ ) {
        if ( fds[i].fd == -1 ) 
            continue;
        if ( fds[i].for_read || fds[i].for_write ) {
            if ( nwait >= DIM (waitbuf) ) {
                DEBUG_SELECT ((stderr, "oops ]\n" ));
                fprintf (stderr, "** Too many objects for WFMO!\n" );
                return -1;
            }
            else {
                waitbuf[nwait++] = fd_to_handle (fds[i].fd);
                DEBUG_SELECT ((stderr, "%c%d ",
                               fds[i].for_read? 'r':'w',fds[i].fd ));
                any = 1;
            }
        }
        fds[i].signaled = 0;
    }
    DEBUG_SELECT ((stderr, "]\n" ));
    if (!any)
        return 0;

    ret = 0;
    code = WaitForMultipleObjects ( nwait, waitbuf, 0, 1000 );
    if (code == WAIT_FAILED ) {
        fprintf (stderr, "** WFMO failed: %d\n",  (int)GetLastError () );
        ret = -1;
    }
    else if ( code == WAIT_TIMEOUT ) {
        fprintf (stderr, "** WFMO timed out\n" );
    }  
    else if ( code >= WAIT_OBJECT_0 && code < WAIT_OBJECT_0 + nwait ) {
        /* This WFMO is a really silly function:  It does return either
         * the index of the signaled object or if 2 objects have been
         * signalled at the same time, the index of the object with the
         * lowest object is returned - so and how do we find out
         * how many objects have been signaled???.
         * The only solution I can imagine is to test each object starting
         * with the returned index individually - how dull.
         */
        any = 0;
        for (i=code - WAIT_OBJECT_0; i < nwait; i++ ) {
            if (WaitForSingleObject ( waitbuf[i], NULL ) == WAIT_OBJECT_0) {
                fds[i].signaled = 1;
                any = 1;
            }
        }
        if (any)
            ret = 1;
        else {
            fprintf (stderr,
                     "** Oops: No signaled objects found after WFMO\n");
            ret = -1;
        }
    }
    else {
        fprintf (stderr, "** WFMO returned %d\n", code );
        ret = -1;
    }

    return ret;
}

#endif /*HAVE_DOSISH_SYSTEM*/









