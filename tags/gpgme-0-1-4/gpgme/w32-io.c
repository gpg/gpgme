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
#include <signal.h>
#include <fcntl.h>
#include <windows.h>
#include "syshdr.h"

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

    DEBUG_SELECT ((stderr,"** fd %d: about to read %d bytes\n", fd, (int)count ));
    if ( !ReadFile ( h, buffer, count, &nread, NULL) ) {
        fprintf (stderr, "** ReadFile failed: ec=%d\n", (int)GetLastError ());
        return -1;
    }
    DEBUG_SELECT ((stderr,"** fd %d:           got %d bytes\n", fd, nread ));

    return nread;
}


int
_gpgme_io_write ( int fd, const void *buffer, size_t count )
{
    int nwritten;
    HANDLE h = fd_to_handle (fd);

    DEBUG_SELECT ((stderr,"** fd %d: about to write %d bytes\n", fd, (int)count ));
    if ( !WriteFile ( h, buffer, count, &nwritten, NULL) ) {
        fprintf (stderr, "** WriteFile failed: ec=%d\n", (int)GetLastError ());
        return -1;
    }
    DEBUG_SELECT ((stderr,"** fd %d:          wrote %d bytes\n", fd, nwritten ));

    return nwritten;
}

int
_gpgme_io_pipe ( int filedes[2], int inherit_idx )
{
    HANDLE r, w;
    SECURITY_ATTRIBUTES sec_attr;

    memset (&sec_attr, 0, sizeof sec_attr );
    sec_attr.nLength = sizeof sec_attr;
    sec_attr.bInheritHandle = FALSE;
    
    if (!CreatePipe ( &r, &w, &sec_attr, 0))
        return -1;
    /* make one end inheritable */
    if ( inherit_idx == 0 ) {
        HANDLE h;
        if (!DuplicateHandle( GetCurrentProcess(), r,
                              GetCurrentProcess(), &h, 0,
                              TRUE, DUPLICATE_SAME_ACCESS ) ) {
            fprintf (stderr, "** DuplicateHandle failed: ec=%d\n",
                     (int)GetLastError());
            CloseHandle (r);
            CloseHandle (w);
            return -1;
        }
        CloseHandle (r);
        r = h;
    }
    else if ( inherit_idx == 1 ) {
        HANDLE h;
        if (!DuplicateHandle( GetCurrentProcess(), w,
                              GetCurrentProcess(), &h, 0,
                              TRUE, DUPLICATE_SAME_ACCESS ) ) {
            fprintf (stderr, "** DuplicateHandle failed: ec=%d\n",
                     (int)GetLastError());
            CloseHandle (r);
            CloseHandle (w);
            return -1;
        }
        CloseHandle (w);
        w = h;
    }

    filedes[0] = handle_to_fd (r);
    filedes[1] = handle_to_fd (w);
    DEBUG_SELECT ((stderr,"** create pipe %p %p %d %d inherit=%d\n", r, w,
                   filedes[0], filedes[1], inherit_idx ));
    return 0;
}

int
_gpgme_io_close ( int fd )
{
    if ( fd == -1 )
        return -1;

    DEBUG_SELECT ((stderr,"** closing handle for fd %d\n", fd));
    if ( !CloseHandle (fd_to_handle (fd)) ) { 
        fprintf (stderr, "** CloseHandle for fd %d failed: ec=%d\n",
                 fd, (int)GetLastError ());
        return -1;
    }

    return 0;
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
    buf = p = xtrymalloc (n);
    if ( !buf )
        return NULL;
    *buf = 0;
    if ( argv[0] )
        p = stpcpy (p, argv[0]);
    for (i = 1; argv[i]; i++)
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
    STARTUPINFO si;
    char *envblock = NULL;
    int cr_flags = CREATE_DEFAULT_ERROR_MODE
                 | GetPriorityClass (GetCurrentProcess ());
    int i;
    char *arg_string;
    int duped_stdin = 0;
    int duped_stderr = 0;
    HANDLE hnul = INVALID_HANDLE_VALUE;
    int debug_me = !!getenv ("GPGME_DEBUG");

    memset (&sec_attr, 0, sizeof sec_attr );
    sec_attr.nLength = sizeof sec_attr;
    sec_attr.bInheritHandle = FALSE;

    arg_string = build_commandline ( argv );
    if (!arg_string )
        return -1; 

    memset (&si, 0, sizeof si);
    si.cb = sizeof (si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = debug_me? SW_SHOW : SW_MINIMIZE;
    si.hStdInput = GetStdHandle (STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle (STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle (STD_ERROR_HANDLE);

    for (i=0; fd_child_list[i].fd != -1; i++ ) {
        if (fd_child_list[i].dup_to == 0 ) {
            si.hStdInput = fd_to_handle (fd_child_list[i].fd);
            DEBUG_SELECT ((stderr,"** using %d for stdin\n", fd_child_list[i].fd ));
            duped_stdin=1;
        }
        else if (fd_child_list[i].dup_to == 1 ) {
            si.hStdOutput = fd_to_handle (fd_child_list[i].fd);
            DEBUG_SELECT ((stderr,"** using %d for stdout\n", fd_child_list[i].fd ));
        }
        else if (fd_child_list[i].dup_to == 2 ) {
            si.hStdError = fd_to_handle (fd_child_list[i].fd);
            DEBUG_SELECT ((stderr,"** using %d for stderr\n", fd_child_list[i].fd ));
            duped_stderr = 1;
        }
    }

    if( !duped_stdin || !duped_stderr ) {
        SECURITY_ATTRIBUTES sa;

        memset (&sa, 0, sizeof sa );
        sa.nLength = sizeof sa;
        sa.bInheritHandle = TRUE;
        hnul = CreateFile ( "/dev/nul",
                            GENERIC_READ|GENERIC_WRITE,
                            FILE_SHARE_READ|FILE_SHARE_WRITE,
                            &sa,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL );
        if ( hnul == INVALID_HANDLE_VALUE ) {
            fprintf (stderr,"can't open `/dev/nul': ec=%d\n",
                     (int)GetLastError () );
            xfree (arg_string);
            return -1;
        }
        /* Make sure that the process has a connected stdin */
        if ( !duped_stdin ) {
            si.hStdInput = hnul;
            DEBUG_SELECT ((stderr,"** using %d for stdin\n", (int)hnul ));
        }
        /* We normally don't want all the normal output */
        if ( !duped_stderr ) {
            if (!debug_me) {
                si.hStdError = hnul;
                DEBUG_SELECT ((stderr,"** using %d for stderr\n", (int)hnul ));
            }
        }
    }

    DEBUG_SELECT ((stderr,"** CreateProcess ...\n"));
    DEBUG_SELECT ((stderr,"** args=`%s'\n", arg_string));
    cr_flags |= CREATE_SUSPENDED; 
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
        xfree (arg_string);
        return -1;
    }

    /* close the /dev/nul handle if used */
    if (hnul != INVALID_HANDLE_VALUE ) {
        if ( !CloseHandle ( hnul ) )
            fprintf (stderr, "** CloseHandle(hnul) failed: ec=%d\n", 
                     (int)GetLastError());
    }

    /* Close the other ends of the pipes */
    for (i=0; fd_parent_list[i].fd != -1; i++ ) {
        DEBUG_SELECT ((stderr,"** Closing fd %d\n", fd_parent_list[i].fd ));
        if ( !CloseHandle ( fd_to_handle (fd_parent_list[i].fd) ) )
            fprintf (stderr, "** CloseHandle failed: ec=%d\n",                 
                     (int)GetLastError());
    }

    DEBUG_SELECT ((stderr,"** CreateProcess ready\n"
                   "**   hProcess=%p  hThread=%p\n"
                   "**   dwProcessID=%d dwThreadId=%d\n",
                   pi.hProcess, pi.hThread, 
                   (int) pi.dwProcessId, (int) pi.dwThreadId));

    if ( ResumeThread ( pi.hThread ) < 0 ) {
        fprintf (stderr, "** ResumeThread failed: ec=%d\n",
                 (int)GetLastError ());
    }

    if ( !CloseHandle (pi.hThread) ) { 
        fprintf (stderr, "** CloseHandle of thread failed: ec=%d\n",
                 (int)GetLastError ());
    }

    return handle_to_pid (pi.hProcess);
}




int
_gpgme_io_waitpid ( int pid, int hang, int *r_status, int *r_signal )
{
    HANDLE proc = fd_to_handle (pid);
    int code, exc, ret = 0;

    *r_status = 0;
    *r_signal = 0;
    code = WaitForSingleObject ( proc, hang? INFINITE : 0 );
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
            DEBUG_SELECT ((stderr,"** GECP pid=%d exit code=%d\n",
                           (int)pid,  exc));
            *r_status = exc;
        }
        ret = 1;
        break;

      case WAIT_TIMEOUT:
        DEBUG_SELECT ((stderr,"** WFSO pid=%d timed out\n", (int)pid));
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
#if 0 /* We can't use WFMO becaus a pipe handle is not a suitable object */
    HANDLE waitbuf[MAXIMUM_WAIT_OBJECTS];
    int code, nwait;
    int i, any, any_write;
    int count;

 restart:
    DEBUG_SELECT ((stderr, "gpgme:select on [ "));
    any = any_write = 0;
    nwait = 0;
    for ( i=0; i < nfds; i++ ) {
        if ( fds[i].fd == -1 ) 
            continue;
        if ( fds[i].for_read || fds[i].for_write ) {
            if ( nwait >= DIM (waitbuf) ) {
                DEBUG_SELECT ((stderr,stderr, "oops ]\n" ));
                fprintf (stderr, "** Too many objects for WFMO!\n" );
                return -1;
            }
            else {
                if ( fds[i].for_read ) 
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

    count = 0;
    for ( i=0; i < nfds; i++ ) {
        if ( fds[i].fd == -1 ) 
            continue;
        if ( fds[i].for_write ) {
            fds[i].signaled = 1;
            any_write =1;
            count++;
        }
    }
    code = WaitForMultipleObjects ( nwait, waitbuf, 0, any_write? 0:1000);
    if (code == WAIT_FAILED ) {
        int le = (int)GetLastError ();
        if ( le == ERROR_INVALID_HANDLE  || le == ERROR_INVALID_EVENT_COUNT ) {
            any = 0;
            for ( i=0; i < nfds; i++ ) {
                if ( fds[i].fd == -1 ) 
                    continue;
                if ( fds[i].for_read /*|| fds[i].for_write*/ ) {
                    int navail;
                    if (PeekNamedPipe (fd_to_handle (fds[i].fd), 
                                       NULL, 0, NULL,
 				       &navail, NULL) && navail ) {
                        fds[i].signaled = 1;
                        any = 1;
                        count++;
                    }
                }
            }
            if (any)
                return count;
            /* find that handle and remove it from the list*/
            for (i=0; i < nwait; i++ ) {
                code = WaitForSingleObject ( waitbuf[i], NULL );
                if (!code) {
                    int k, j = handle_to_fd (waitbuf[i]);

                    fprintf (stderr, "** handle meanwhile signaled %d\n", j);
                    for (k=0 ; k < nfds; k++ ) {
                        if ( fds[k].fd == j ) {
                            fds[k].signaled = 1;
                            count++;
                            return count; 
                        }
                    }
                    fprintf (stderr, "** oops, or not???\n");
                }
                if ( GetLastError () == ERROR_INVALID_HANDLE) {
                    int k, j = handle_to_fd (waitbuf[i]);
                    
                    fprintf (stderr, "** WFMO invalid handle %d removed\n", j);
                    for (k=0 ; k < nfds; i++ ) {
                        if ( fds[k].fd == j ) {
                            fds[k].for_read = fds[k].for_write = 0;
                            goto restart;
                        }
                    }
                    fprintf (stderr, "** oops, or not???\n");
                }
            }
        }

        fprintf (stderr, "** WFMO failed: %d\n", le );
        count = -1;
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
                count++;
            }
        }
        if (!any) {
            fprintf (stderr,
                     "** Oops: No signaled objects found after WFMO\n");
            count = -1;
        }
    }
    else {
        fprintf (stderr, "** WFMO returned %d\n", code );
        count = -1;
    }

    return count;
#else  /* This is the code we use */
    int i, any, count;
    int once_more = 0;

    DEBUG_SELECT ((stderr, "gpgme:fakedselect on [ "));
    any = 0;
    for ( i=0; i < nfds; i++ ) {
        if ( fds[i].fd == -1 ) 
            continue;
        if ( fds[i].for_read || fds[i].for_write ) {
            DEBUG_SELECT ((stderr, "%c%d ",
                           fds[i].for_read? 'r':'w',fds[i].fd ));
            any = 1;
        }
        fds[i].signaled = 0;
    }
    DEBUG_SELECT ((stderr, "]\n" ));
    if (!any) 
        return 0;

 restart:
    count = 0;
    /* no way to see whether a handle is ready fro writing, signal all */
    for ( i=0; i < nfds; i++ ) {
        if ( fds[i].fd == -1 ) 
            continue;
        if ( fds[i].for_write ) {
            fds[i].signaled = 1;
            count++;
        }
    }

    /* now peek on all read handles */
    for ( i=0; i < nfds; i++ ) {
        if ( fds[i].fd == -1 ) 
            continue;
        if ( fds[i].for_read ) {
            int navail;

            if ( !PeekNamedPipe (fd_to_handle (fds[i].fd),
                                 NULL, 0, NULL, &navail, NULL) ) {
                fprintf (stderr, "** select: PeekFile failed: ec=%d\n",
                         (int)GetLastError ());
            }
            else if ( navail ) {
                /*fprintf (stderr, "** fd %d has %d bytes to read\n",
                  fds[i].fd, navail );*/
                fds[i].signaled = 1;
                count++;
            }
        }
    }
    if ( !once_more && !count ) {
        /* once more but after relinquishing our timeslot */
        once_more = 1;
        Sleep (0);
        goto restart;
    }

    if ( count ) {
        DEBUG_SELECT ((stderr, "gpgme:      signaled [ "));
        for ( i=0; i < nfds; i++ ) {
            if ( fds[i].fd == -1 ) 
                continue;
            if ( (fds[i].for_read || fds[i].for_write) && fds[i].signaled ) {
                DEBUG_SELECT ((stderr, "%c%d ",
                               fds[i].for_read? 'r':'w',fds[i].fd ));
            }
        }
        DEBUG_SELECT ((stderr, "]\n" ));
    }
    
    return count;
#endif
}

#endif /*HAVE_DOSISH_SYSTEM*/









