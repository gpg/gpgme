/* w32-io.c - W32 API I/O functions.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003 g10 Code GmbH

   This file is part of GPGME.
 
   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with GPGME; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <windows.h>
#include <io.h>

#include "util.h"
#include "sema.h"
#include "io.h"


/* We assume that a HANDLE can be represented by an int which should
   be true for all i386 systems (HANDLE is defined as void *) and
   these are the only systems for which Windows is available.  Further
   we assume that -1 denotes an invalid handle.  */

#define fd_to_handle(a)  ((HANDLE)(a))
#define handle_to_fd(a)  ((int)(a))
#define pid_to_handle(a) ((HANDLE)(a))
#define handle_to_pid(a) ((int)(a))

#define READBUF_SIZE 4096
#define WRITEBUF_SIZE 4096
#define MAX_READERS 20
#define MAX_WRITERS 20

static struct {
    int inuse;
    int fd;
    void (*handler)(int,void*);
    void *value;
} notify_table[256];
DEFINE_STATIC_LOCK (notify_table_lock);


struct reader_context_s {
    HANDLE file_hd;
    HANDLE thread_hd;	
    DECLARE_LOCK (mutex);

    int stop_me;
    int eof;
    int eof_shortcut;
    int error;
    int error_code;

    HANDLE have_data_ev;  /* manually reset */
    HANDLE have_space_ev; /* auto reset */
    HANDLE stopped;
    size_t readpos, writepos;
    char buffer[READBUF_SIZE];
};


static struct {
    volatile int used;
    int fd;
    struct reader_context_s *context;
} reader_table[MAX_READERS];
static int reader_table_size= MAX_READERS;
DEFINE_STATIC_LOCK (reader_table_lock);


struct writer_context_s {
    HANDLE file_hd;
    HANDLE thread_hd;	
    DECLARE_LOCK (mutex);

    int stop_me;
    int error;
    int error_code;

    HANDLE have_data;  /* manually reset */
    HANDLE is_empty;
    HANDLE stopped;
    size_t nbytes; 
    char buffer[WRITEBUF_SIZE];
};


static struct {
    volatile int used;
    int fd;
    struct writer_context_s *context;
} writer_table[MAX_WRITERS];
static int writer_table_size= MAX_WRITERS;
DEFINE_STATIC_LOCK (writer_table_lock);



static HANDLE
set_synchronize (HANDLE h)
{
    HANDLE tmp;
    
    /* For NT we have to set the sync flag.  It seems that the only
     * way to do it is by duplicating the handle.  Tsss.. */
    if (!DuplicateHandle( GetCurrentProcess(), h,
                          GetCurrentProcess(), &tmp,
                          EVENT_MODIFY_STATE|SYNCHRONIZE, FALSE, 0 ) ) {
        DEBUG1 ("** Set SYNCRONIZE failed: ec=%d\n", (int)GetLastError());
    }
    else {
        CloseHandle (h);
        h = tmp;
    }
    return h;
}



static DWORD CALLBACK 
reader (void *arg)
{
    struct reader_context_s *c = arg;
    int nbytes;
    DWORD nread;

    DEBUG2 ("reader thread %p for file %p started", c->thread_hd, c->file_hd );
    for (;;) {
        LOCK (c->mutex);
        /* leave a 1 byte gap so that we can see whether it is empty or full*/
        if ((c->writepos + 1) % READBUF_SIZE == c->readpos) { 
            /* wait for space */
            if (!ResetEvent (c->have_space_ev) )
                DEBUG1 ("ResetEvent failed: ec=%d", (int)GetLastError ());
            UNLOCK (c->mutex);
            DEBUG1 ("reader thread %p: waiting for space ...", c->thread_hd );
            WaitForSingleObject (c->have_space_ev, INFINITE);
            DEBUG1 ("reader thread %p: got space", c->thread_hd );
            LOCK (c->mutex);
       	}
        if ( c->stop_me ) {
            UNLOCK (c->mutex);
            break;
        }
        nbytes = (c->readpos + READBUF_SIZE - c->writepos-1) % READBUF_SIZE;
        if ( nbytes > READBUF_SIZE - c->writepos )
            nbytes = READBUF_SIZE - c->writepos;
        UNLOCK (c->mutex);

        DEBUG2 ("reader thread %p: reading %d bytes", c->thread_hd, nbytes );
        if ( !ReadFile ( c->file_hd,
                         c->buffer+c->writepos, nbytes, &nread, NULL) ) {
            c->error_code = (int)GetLastError ();
            if (c->error_code == ERROR_BROKEN_PIPE ) {
                c->eof=1;
                DEBUG1 ("reader thread %p: got eof (broken pipe)",
                        c->thread_hd );
            }
            else {
                c->error = 1;
                DEBUG2 ("reader thread %p: read error: ec=%d",
                        c->thread_hd, c->error_code );
            }
            break;
        }
        if ( !nread ) {
            c->eof = 1;
            DEBUG1 ("reader thread %p: got eof", c->thread_hd );
            break;
        }
        DEBUG2 ("reader thread %p: got %d bytes", c->thread_hd, (int)nread );
      
        LOCK (c->mutex);
        if (c->stop_me) {
            UNLOCK (c->mutex);
            break;
        }
        c->writepos = (c->writepos + nread) % READBUF_SIZE;
        if ( !SetEvent (c->have_data_ev) )
            DEBUG1 ("SetEvent failed: ec=%d", (int)GetLastError ());
        UNLOCK (c->mutex);
    }
    /* indicate that we have an error or eof */
    if ( !SetEvent (c->have_data_ev) )
        DEBUG1 ("SetEvent failed: ec=%d", (int)GetLastError ());
    DEBUG1 ("reader thread %p ended", c->thread_hd );
    SetEvent (c->stopped);

    return 0;
}


static struct reader_context_s *
create_reader (HANDLE fd)
{
    struct reader_context_s *c;
    SECURITY_ATTRIBUTES sec_attr;
    DWORD tid;

    DEBUG1 ("creating new read thread for file handle %p", fd );
    memset (&sec_attr, 0, sizeof sec_attr );
    sec_attr.nLength = sizeof sec_attr;
    sec_attr.bInheritHandle = FALSE;

    c = calloc (1, sizeof *c );
    if (!c)
        return NULL;

    c->file_hd = fd;
    c->have_data_ev = CreateEvent (&sec_attr, TRUE, FALSE, NULL);
    c->have_space_ev = CreateEvent (&sec_attr, FALSE, TRUE, NULL);
    c->stopped = CreateEvent (&sec_attr, TRUE, FALSE, NULL);
    if (!c->have_data_ev || !c->have_space_ev || !c->stopped ) {
        DEBUG1 ("** CreateEvent failed: ec=%d\n", (int)GetLastError ());
        if (c->have_data_ev)
            CloseHandle (c->have_data_ev);
        if (c->have_space_ev)
            CloseHandle (c->have_space_ev);
        if (c->stopped)
            CloseHandle (c->stopped);
        free (c);
        return NULL;
    }

    c->have_data_ev = set_synchronize (c->have_data_ev);
    INIT_LOCK (c->mutex);

    c->thread_hd = CreateThread (&sec_attr, 0, reader, c, 0, &tid );
    if (!c->thread_hd) {
        DEBUG1 ("** failed to create reader thread: ec=%d\n",
                 (int)GetLastError ());
        DESTROY_LOCK (c->mutex);
        if (c->have_data_ev)
            CloseHandle (c->have_data_ev);
        if (c->have_space_ev)
            CloseHandle (c->have_space_ev);
        if (c->stopped)
            CloseHandle (c->stopped);
        free (c);
        return NULL;
    }    

    return c;
}

static void
destroy_reader (struct reader_context_s *c)
{
    LOCK (c->mutex);
    c->stop_me = 1;
    if (c->have_space_ev) 
        SetEvent (c->have_space_ev);
    UNLOCK (c->mutex);

    DEBUG1 ("waiting for thread %p termination ...", c->thread_hd );
    WaitForSingleObject (c->stopped, INFINITE);
    DEBUG1 ("thread %p has terminated", c->thread_hd );
    
    if (c->stopped)
        CloseHandle (c->stopped);
    if (c->have_data_ev)
        CloseHandle (c->have_data_ev);
    if (c->have_space_ev)
        CloseHandle (c->have_space_ev);
    CloseHandle (c->thread_hd);
    DESTROY_LOCK (c->mutex);
    free (c);
}


/* 
 * Find a reader context or create a new one 
 * Note that the reader context will last until a io_close.
 */
static struct reader_context_s *
find_reader (int fd, int start_it)
{
    int i;

    for (i=0; i < reader_table_size ; i++ ) {
        if ( reader_table[i].used && reader_table[i].fd == fd )
            return reader_table[i].context;
    }
    if (!start_it)
        return NULL;

    LOCK (reader_table_lock);
    for (i=0; i < reader_table_size; i++ ) {
        if (!reader_table[i].used) {
            reader_table[i].fd = fd;
            reader_table[i].context = create_reader (fd_to_handle (fd));
            reader_table[i].used = 1;
            UNLOCK (reader_table_lock);
            return reader_table[i].context;
        }
    }
    UNLOCK (reader_table_lock);
    return NULL;
}


static void
kill_reader (int fd)
{
    int i;

    LOCK (reader_table_lock);
    for (i=0; i < reader_table_size; i++ ) {
        if (reader_table[i].used && reader_table[i].fd == fd ) {
            destroy_reader (reader_table[i].context);
            reader_table[i].context = NULL;
            reader_table[i].used = 0;
            break;
        }
    }
    UNLOCK (reader_table_lock);
}



int
_gpgme_io_read ( int fd, void *buffer, size_t count )
{
    int nread;
    struct reader_context_s *c = find_reader (fd,1);

    DEBUG2 ("fd %d: about to read %d bytes\n", fd, (int)count );
    if ( !c ) {
        DEBUG0 ( "no reader thread\n");
        return -1;
    }
    if (c->eof_shortcut) {
        DEBUG1 ("fd %d: EOF (again)", fd );
        return 0;
    }

    LOCK (c->mutex);
    if (c->readpos == c->writepos && !c->error) { /*no data avail*/
        UNLOCK (c->mutex);
        DEBUG2 ("fd %d: waiting for data from thread %p", fd, c->thread_hd);
        WaitForSingleObject (c->have_data_ev, INFINITE);
        DEBUG2 ("fd %d: data from thread %p available", fd, c->thread_hd);
        LOCK (c->mutex);
    }
    
    if (c->readpos == c->writepos || c->error) {
        UNLOCK (c->mutex);
        c->eof_shortcut = 1;
        if (c->eof) {
            DEBUG1 ("fd %d: EOF", fd );
            return 0;
        }
        if (!c->error) {
            DEBUG1 ("fd %d: EOF but eof flag not set", fd );
            return 0;
        }
        DEBUG1 ("fd %d: read error", fd );
        return -1;
    }
      
    nread = c->readpos < c->writepos? c->writepos - c->readpos
                                    : READBUF_SIZE - c->readpos;
    if (nread > count)
        nread = count;
    memcpy (buffer, c->buffer+c->readpos, nread);
    c->readpos = (c->readpos + nread) % READBUF_SIZE;
    if (c->readpos == c->writepos && !c->eof) {
        if ( !ResetEvent (c->have_data_ev) )
            DEBUG1 ("ResetEvent failed: ec=%d", (int)GetLastError ());
    }
    if (!SetEvent (c->have_space_ev))
        DEBUG1 ("SetEvent failed: ec=%d", (int)GetLastError ());
    UNLOCK (c->mutex);

    DEBUG2 ("fd %d: got %d bytes\n", fd, nread );

    return nread;
}



/*
 * The writer does use a simple buffering strategy so that we are
 * informed about write errors as soon as possible (i.e. with the the
 * next call to the write function
 */
static DWORD CALLBACK 
writer (void *arg)
{
    struct writer_context_s *c = arg;
    DWORD nwritten;

    DEBUG2 ("writer thread %p for file %p started", c->thread_hd, c->file_hd );
    for (;;) {
        LOCK (c->mutex);
        if ( !c->nbytes ) { 
            if (!ResetEvent (c->have_data) )
                DEBUG1 ("ResetEvent failed: ec=%d", (int)GetLastError ());
            UNLOCK (c->mutex);
            DEBUG1 ("writer thread %p: idle ...", c->thread_hd );
            WaitForSingleObject (c->have_data, INFINITE);
            DEBUG1 ("writer thread %p: got data to send", c->thread_hd );
            LOCK (c->mutex);
       	}
        if ( c->stop_me ) {
            UNLOCK (c->mutex);
            break;
        }
        UNLOCK (c->mutex);

        DEBUG2 ("writer thread %p: writing %d bytes",
                c->thread_hd, c->nbytes );
        if ( c->nbytes && !WriteFile ( c->file_hd,  c->buffer, c->nbytes,
                                       &nwritten, NULL)) {
            c->error_code = (int)GetLastError ();
            c->error = 1;
            DEBUG2 ("writer thread %p: write error: ec=%d",
                    c->thread_hd, c->error_code );
            break;
        }
        DEBUG2 ("writer thread %p: wrote %d bytes",
                c->thread_hd, (int)nwritten );
      
        LOCK (c->mutex);
        c->nbytes -= nwritten;
        if (c->stop_me) {
            UNLOCK (c->mutex);
            break;
        }
        if ( !c->nbytes ) {
            if ( !SetEvent (c->is_empty) )
                DEBUG1 ("SetEvent failed: ec=%d", (int)GetLastError ());
        }
        UNLOCK (c->mutex);
    }
    /* indicate that we have an error  */
    if ( !SetEvent (c->is_empty) )
        DEBUG1 ("SetEvent failed: ec=%d", (int)GetLastError ());
    DEBUG1 ("writer thread %p ended", c->thread_hd );
    SetEvent (c->stopped);

    return 0;
}


static struct writer_context_s *
create_writer (HANDLE fd)
{
    struct writer_context_s *c;
    SECURITY_ATTRIBUTES sec_attr;
    DWORD tid;

    DEBUG1 ("creating new write thread for file handle %p", fd );
    memset (&sec_attr, 0, sizeof sec_attr );
    sec_attr.nLength = sizeof sec_attr;
    sec_attr.bInheritHandle = FALSE;

    c = calloc (1, sizeof *c );
    if (!c)
        return NULL;

    c->file_hd = fd;
    c->have_data = CreateEvent (&sec_attr, FALSE, FALSE, NULL);
    c->is_empty  = CreateEvent (&sec_attr, TRUE, TRUE, NULL);
    c->stopped = CreateEvent (&sec_attr, TRUE, FALSE, NULL);
    if (!c->have_data || !c->is_empty || !c->stopped ) {
        DEBUG1 ("** CreateEvent failed: ec=%d\n", (int)GetLastError ());
        if (c->have_data)
            CloseHandle (c->have_data);
        if (c->is_empty)
            CloseHandle (c->is_empty);
        if (c->stopped)
            CloseHandle (c->stopped);
        free (c);
        return NULL;
    }

    c->is_empty = set_synchronize (c->is_empty);
    INIT_LOCK (c->mutex);

    c->thread_hd = CreateThread (&sec_attr, 0, writer, c, 0, &tid );
    if (!c->thread_hd) {
        DEBUG1 ("** failed to create writer thread: ec=%d\n",
                 (int)GetLastError ());
        DESTROY_LOCK (c->mutex);
        if (c->have_data)
            CloseHandle (c->have_data);
        if (c->is_empty)
            CloseHandle (c->is_empty);
        if (c->stopped)
            CloseHandle (c->stopped);
        free (c);
        return NULL;
    }    

    return c;
}

static void
destroy_writer (struct writer_context_s *c)
{
    LOCK (c->mutex);
    c->stop_me = 1;
    if (c->have_data) 
        SetEvent (c->have_data);
    UNLOCK (c->mutex);

    DEBUG1 ("waiting for thread %p termination ...", c->thread_hd );
    WaitForSingleObject (c->stopped, INFINITE);
    DEBUG1 ("thread %p has terminated", c->thread_hd );
    
    if (c->stopped)
        CloseHandle (c->stopped);
    if (c->have_data)
        CloseHandle (c->have_data);
    if (c->is_empty)
        CloseHandle (c->is_empty);
    CloseHandle (c->thread_hd);
    DESTROY_LOCK (c->mutex);
    free (c);
}


/* 
 * Find a writer context or create a new one 
 * Note that the writer context will last until a io_close.
 */
static struct writer_context_s *
find_writer (int fd, int start_it)
{
    int i;

    for (i=0; i < writer_table_size ; i++ ) {
        if ( writer_table[i].used && writer_table[i].fd == fd )
            return writer_table[i].context;
    }
    if (!start_it)
        return NULL;

    LOCK (writer_table_lock);
    for (i=0; i < writer_table_size; i++ ) {
        if (!writer_table[i].used) {
            writer_table[i].fd = fd;
            writer_table[i].context = create_writer (fd_to_handle (fd));
            writer_table[i].used = 1;
            UNLOCK (writer_table_lock);
            return writer_table[i].context;
        }
    }
    UNLOCK (writer_table_lock);
    return NULL;
}


static void
kill_writer (int fd)
{
    int i;

    LOCK (writer_table_lock);
    for (i=0; i < writer_table_size; i++ ) {
        if (writer_table[i].used && writer_table[i].fd == fd ) {
            destroy_writer (writer_table[i].context);
            writer_table[i].context = NULL;
            writer_table[i].used = 0;
            break;
        }
    }
    UNLOCK (writer_table_lock);
}




int
_gpgme_io_write ( int fd, const void *buffer, size_t count )
{
    struct writer_context_s *c = find_writer (fd,1);

    DEBUG2 ("fd %d: about to write %d bytes\n", fd, (int)count );
    if ( !c ) {
        DEBUG0 ( "no writer thread\n");
        return -1;
    }

    LOCK (c->mutex);
    if ( c->nbytes ) { /* bytes are pending for send */
        UNLOCK (c->mutex);
        DEBUG2 ("fd %d: waiting for empty buffer in thread %p",
                fd, c->thread_hd);
        WaitForSingleObject (c->is_empty, INFINITE);
        DEBUG2 ("fd %d: thread %p buffer is empty", fd, c->thread_hd);
        assert (!c->nbytes);
        LOCK (c->mutex);
    }
    
    if ( c->error) {
        UNLOCK (c->mutex);
        DEBUG1 ("fd %d: write error", fd );
        return -1;
    }
      
    if (count > WRITEBUF_SIZE)
        count = WRITEBUF_SIZE;
    memcpy (c->buffer, buffer, count);
    c->nbytes = count;
    if (!SetEvent (c->have_data))
        DEBUG1 ("SetEvent failed: ec=%d", (int)GetLastError ());
    UNLOCK (c->mutex);

    DEBUG2 ("fd %d:         copied %d bytes\n",
                   fd, (int)count );
    return (int)count;
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
            DEBUG1 ("DuplicateHandle failed: ec=%d\n", (int)GetLastError());
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
            DEBUG1 ("DuplicateHandle failed: ec=%d\n", (int)GetLastError());
            CloseHandle (r);
            CloseHandle (w);
            return -1;
        }
        CloseHandle (w);
        w = h;
    }

    filedes[0] = handle_to_fd (r);
    filedes[1] = handle_to_fd (w);
    DEBUG5 ("CreatePipe %p %p %d %d inherit=%d\n", r, w,
                   filedes[0], filedes[1], inherit_idx );
    return 0;
}

int
_gpgme_io_close ( int fd )
{
    int i;
    void (*handler)(int, void*) = NULL;
    void *value = NULL;

    if ( fd == -1 )
        return -1;

    DEBUG1 ("** closing handle for fd %d\n", fd);
    kill_reader (fd);
    kill_writer (fd);
    LOCK (notify_table_lock);
    for ( i=0; i < DIM (notify_table); i++ ) {
        if (notify_table[i].inuse && notify_table[i].fd == fd) {
            handler = notify_table[i].handler;
            value   = notify_table[i].value;
            notify_table[i].handler = NULL;
            notify_table[i].value = NULL;
            notify_table[i].inuse = 0;
            break;
        }
    }
    UNLOCK (notify_table_lock);
    if (handler)
        handler (fd, value);

    if ( !CloseHandle (fd_to_handle (fd)) ) { 
        DEBUG2 ("CloseHandle for fd %d failed: ec=%d\n",
                 fd, (int)GetLastError ());
        return -1;
    }

    return 0;
}

int
_gpgme_io_set_close_notify (int fd, void (*handler)(int, void*), void *value)
{
    int i;

    assert (fd != -1);

    LOCK (notify_table_lock);
    for (i=0; i < DIM (notify_table); i++ ) {
        if ( notify_table[i].inuse && notify_table[i].fd == fd )
            break;
    }
    if ( i == DIM (notify_table) ) {
        for (i=0; i < DIM (notify_table); i++ ) {
            if ( !notify_table[i].inuse )
                break;
        }
    }
    if ( i == DIM (notify_table) ) {
        UNLOCK (notify_table_lock);
        return -1;
    }
    notify_table[i].fd = fd;
    notify_table[i].handler = handler;
    notify_table[i].value = value;
    notify_table[i].inuse = 1;
    UNLOCK (notify_table_lock);
    DEBUG2 ("set notification for fd %d (idx=%d)", fd, i );
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
        n += strlen (argv[i]) + 2 + 1; /* 2 extra bytes for possible quoting */
    buf = p = malloc (n);
    if ( !buf )
        return NULL;
    *buf = 0;
    if ( argv[0] )
        p = stpcpy (p, argv[0]);
    for (i = 1; argv[i]; i++) {
        if (!*argv[i])
            p = stpcpy (p, " \"\"");
        else
            p = stpcpy (stpcpy (p, " "), argv[i]);
    }

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
    /* FIXME.  */
    int debug_me = 0;

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
            DEBUG1 ("using %d for stdin", fd_child_list[i].fd );
            duped_stdin=1;
        }
        else if (fd_child_list[i].dup_to == 1 ) {
            si.hStdOutput = fd_to_handle (fd_child_list[i].fd);
            DEBUG1 ("using %d for stdout", fd_child_list[i].fd );
        }
        else if (fd_child_list[i].dup_to == 2 ) {
            si.hStdError = fd_to_handle (fd_child_list[i].fd);
            DEBUG1 ("using %d for stderr", fd_child_list[i].fd );
            duped_stderr = 1;
        }
    }

    if( !duped_stdin || !duped_stderr ) {
        SECURITY_ATTRIBUTES sa;

        memset (&sa, 0, sizeof sa );
        sa.nLength = sizeof sa;
        sa.bInheritHandle = TRUE;
        hnul = CreateFile ( "nul",
                            GENERIC_READ|GENERIC_WRITE,
                            FILE_SHARE_READ|FILE_SHARE_WRITE,
                            &sa,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL );
        if ( hnul == INVALID_HANDLE_VALUE ) {
            DEBUG1 ("can't open `nul': ec=%d\n", (int)GetLastError ());
            free (arg_string);
            return -1;
        }
        /* Make sure that the process has a connected stdin */
        if ( !duped_stdin ) {
            si.hStdInput = hnul;
            DEBUG1 ("using %d for dummy stdin", (int)hnul );
        }
        /* We normally don't want all the normal output */
        if ( !duped_stderr ) {
            si.hStdError = hnul;
            DEBUG1 ("using %d for dummy stderr", (int)hnul );
        }
    }

    DEBUG2 ("CreateProcess, path=`%s' args=`%s'", path, arg_string);
    cr_flags |= CREATE_SUSPENDED; 
    if ( !CreateProcessA (path,
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
        DEBUG1 ("CreateProcess failed: ec=%d\n", (int) GetLastError ());
        free (arg_string);
        return -1;
    }

    /* close the /dev/nul handle if used */
    if (hnul != INVALID_HANDLE_VALUE ) {
        if ( !CloseHandle ( hnul ) )
            DEBUG1 ("CloseHandle(hnul) failed: ec=%d\n", (int)GetLastError());
    }

    /* Close the other ends of the pipes */
    for (i = 0; fd_parent_list[i].fd != -1; i++)
      _gpgme_io_close (fd_parent_list[i].fd);

    DEBUG4 ("CreateProcess ready\n"
            "-   hProcess=%p  hThread=%p\n"
            "-   dwProcessID=%d dwThreadId=%d\n",
            pi.hProcess, pi.hThread, 
            (int) pi.dwProcessId, (int) pi.dwThreadId);

    if ( ResumeThread ( pi.hThread ) < 0 ) {
        DEBUG1 ("ResumeThread failed: ec=%d\n", (int)GetLastError ());
    }

    if ( !CloseHandle (pi.hThread) ) { 
        DEBUG1 ("CloseHandle of thread failed: ec=%d\n",
                 (int)GetLastError ());
    }

    return handle_to_pid (pi.hProcess);
}




int
_gpgme_io_waitpid ( int pid, int hang, int *r_status, int *r_signal )
{
    HANDLE proc = fd_to_handle (pid);
    int code, ret = 0;
    DWORD exc;

    *r_status = 0;
    *r_signal = 0;
    code = WaitForSingleObject ( proc, hang? INFINITE : 0 );
    switch (code) {
      case WAIT_FAILED:
        DEBUG2 ("WFSO pid=%d failed: %d\n", (int)pid, (int)GetLastError () );
        break;

      case WAIT_OBJECT_0:
        if (!GetExitCodeProcess (proc, &exc)) {
            DEBUG2 ("** GECP pid=%d failed: ec=%d\n",
                    (int)pid, (int)GetLastError () );
            *r_status = 4; 
        }
        else {
            DEBUG2 ("GECP pid=%d exit code=%d\n", (int)pid,  exc);
            *r_status = exc;
        }
        ret = 1;
        break;

      case WAIT_TIMEOUT:
        if (hang)
            DEBUG1 ("WFSO pid=%d timed out\n", (int)pid);
        break;

      default:
        DEBUG2 ("WFSO pid=%d returned %d\n", (int)pid, code );
        break;
    }
    return ret;
}

int
_gpgme_io_kill ( int pid, int hard )
{
    HANDLE proc = fd_to_handle (pid);

    #warning I am not sure how to kill a process
    /* fixme: figure out how this can be done */
    return 0;
}



/*
 * Select on the list of fds.
 * Returns: -1 = error
 *           0 = timeout or nothing to select
 *          >0 = number of signaled fds
 */
int
_gpgme_io_select ( struct io_select_fd_s *fds, size_t nfds, int nonblock )
{
    HANDLE waitbuf[MAXIMUM_WAIT_OBJECTS];
    int    waitidx[MAXIMUM_WAIT_OBJECTS];
    int code, nwait;
    int i, any;
    int count;
    void *dbg_help;

 restart:
    DEBUG_BEGIN (dbg_help, 3, "select on [ ");
    any = 0;
    nwait = 0;
    count = 0;
    for ( i=0; i < nfds; i++ ) {
        if ( fds[i].fd == -1 ) 
            continue;
        fds[i].signaled = 0;
        if ( fds[i].for_read || fds[i].for_write ) {
            if ( fds[i].frozen ) {
                DEBUG_ADD1 (dbg_help, "f%d ", fds[i].fd );
            }
            else if ( fds[i].for_read ) {
                struct reader_context_s *c = find_reader (fds[i].fd,1);
                
                if (!c) { 
                    DEBUG1 ("oops: no reader thread for fd %d", fds[i].fd);
                }
                else {
                    if ( nwait >= DIM (waitbuf) ) {
                        DEBUG_END (dbg_help, "oops ]");
                        DEBUG0 ("Too many objects for WFMO!" );
                        return -1;
                    }
                    waitidx[nwait]   = i;
                    waitbuf[nwait++] = c->have_data_ev;
                }
                DEBUG_ADD1 (dbg_help, "r%d ", fds[i].fd );
                any = 1;
            }
            else if ( fds[i].for_write ) {
                struct writer_context_s *c = find_writer (fds[i].fd,1);
                
                if (!c) { 
                    DEBUG1 ("oops: no writer thread for fd %d", fds[i].fd);
                }
                else {
                    if ( nwait >= DIM (waitbuf) ) {
                        DEBUG_END (dbg_help, "oops ]");
                        DEBUG0 ("Too many objects for WFMO!" );
                        return -1;
                    }
                    LOCK (c->mutex);
                    if ( !c->nbytes ) {
                        waitidx[nwait]   = i;
                        waitbuf[nwait++] = c->is_empty;
                        DEBUG_ADD1 (dbg_help, "w%d ", fds[i].fd );
                        any = 1;
                    }
                    else {
                        DEBUG_ADD1 (dbg_help, "w%d(ignored) ", fds[i].fd );
                    }
                    UNLOCK (c->mutex);
                }
            }
        }
    }
    DEBUG_END (dbg_help, "]");
    if (!any) 
        return 0;

    code = WaitForMultipleObjects ( nwait, waitbuf, 0, nonblock ? 0 : 1000);
    if ( code >= WAIT_OBJECT_0 && code < WAIT_OBJECT_0 + nwait ) {
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
                assert (waitidx[i] >=0 && waitidx[i] < nfds);
                fds[waitidx[i]].signaled = 1;
                any = 1;
                count++;
            }
        }
        if (!any) {
            DEBUG0 ("Oops: No signaled objects found after WFMO");
            count = -1;
        }
    }
    else if ( code == WAIT_TIMEOUT ) {
        DEBUG0 ("WFMO timed out\n" );
    }  
    else if (code == WAIT_FAILED ) {
        int le = (int)GetLastError ();
        if ( le == ERROR_INVALID_HANDLE ) {
            int k, j = handle_to_fd (waitbuf[i]);
                    
            DEBUG1 ("WFMO invalid handle %d removed\n", j);
            for (k=0 ; k < nfds; i++ ) {
                if ( fds[k].fd == j ) {
                    fds[k].for_read = fds[k].for_write = 0;
                    goto restart;
                }
            }
            DEBUG0 (" oops, or not???\n");
        }
        DEBUG1 ("WFMO failed: %d\n", le );
        count = -1;
    }
    else {
        DEBUG1 ("WFMO returned %d\n", code );
        count = -1;
    }

    if ( count ) {
        DEBUG_BEGIN (dbg_help, 3, " signaled [ ");
        for ( i=0; i < nfds; i++ ) {
            if ( fds[i].fd == -1 ) 
                continue;
            if ( (fds[i].for_read || fds[i].for_write) && fds[i].signaled ) {
                DEBUG_ADD2 (dbg_help, "%c%d ",
                            fds[i].for_read? 'r':'w',fds[i].fd );
            }
        }
        DEBUG_END (dbg_help, "]");
    }
    
    return count;
}
