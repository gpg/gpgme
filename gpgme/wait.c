/* wait.c 
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *      Copyright (C) 2001 g10 Code GmbH
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include "syshdr.h"

#include "util.h"
#include "context.h"
#include "ops.h"
#include "wait.h"
#include "sema.h"
#include "io.h"

struct wait_item_s;
struct proc_s;

static struct proc_s *proc_queue;
DEFINE_STATIC_LOCK (proc_queue_lock);

static int fd_table_size;
static struct io_select_fd_s *fd_table;
DEFINE_STATIC_LOCK (fd_table_lock);

static void (*idle_function) (void);


struct proc_s {
    struct proc_s *next;
    int pid;
    GpgmeCtx ctx;
    struct wait_item_s *handler_list;
    int ready;
};

struct wait_item_s {
    struct wait_item_s *next;
    int (*handler)(void*,int,int);
    void *handler_value;
    int inbound;       /* this is an inbound data handler fd */
    struct proc_s *proc; /* backlink */
    int ready;
    int frozen; /* copy of the frozen flag from the fd_table */
};



static int do_select ( void );
static void run_idle (void);


/* only to be called with a locked proc_queue */
static int
count_running_fds ( struct proc_s *proc )
{
    struct wait_item_s *q;
    int count = 0;

    for (q=proc->handler_list; q; q=q->next) {
        if ( !q->frozen && !q->ready )
            count++;
    }
    return count;
}

/* only to be called with a locked proc_queue */
static void
set_process_ready ( struct proc_s *proc )
{
    struct wait_item_s *q, *q2;
    int i;

    assert (proc);
    DEBUG2 ("set_process_ready(%p) pid=%d", proc, proc->pid );
    LOCK (fd_table_lock);
    for (q = proc->handler_list; q; q=q2) {
        q2 = q->next;
        for (i=0; i < fd_table_size; i++ ) {
            if (fd_table[i].fd != -1 && q == fd_table[i].opaque ) {
                fd_table[i].opaque = NULL;
                fd_table[i].fd = -1;
            }
        }
        xfree (q);
    }
    UNLOCK (fd_table_lock);
    proc->handler_list = NULL;
    proc->ready = 1;
}

void
_gpgme_remove_proc_from_wait_queue ( int pid )
{
    struct proc_s *proc, *last;

    DEBUG1 ("removing process %d", pid );
    LOCK (proc_queue_lock);
    for (last=NULL, proc=proc_queue; proc; last = proc, proc = proc->next ) {
        if (proc->pid == pid ) {
            set_process_ready (proc);
            if (!last) 
                proc_queue = proc->next;
            else 
                last->next = proc->next;
            xfree (proc);
            break;
        }
    }
    UNLOCK (proc_queue_lock);
}


/**
 * gpgme_wait:
 * @c: 
 * @hang: 
 * 
 * Wait for a finished request, if @c is given the function does only
 * wait on a finished request for that context, otherwise it will return
 * on any request.  When @hang is true the function will wait, otherwise
 * it will return immediately when there is no pending finished request.
 * 
 * Return value: Context of the finished request or NULL if @hang is false
 *  and no (or the given) request has finished.
 **/
GpgmeCtx 
gpgme_wait ( GpgmeCtx c, int hang ) 
{
    return _gpgme_wait_on_condition ( c, hang, NULL );
}

GpgmeCtx 
_gpgme_wait_on_condition ( GpgmeCtx c, int hang, volatile int *cond )
{
    DEBUG3 ("waiting... ctx=%p hang=%d cond=%p", c, hang, cond );
    do {
        int any = 0;
        struct proc_s *proc;

        do_select();

        if ( cond && *cond )
            hang = 0;
        else {
            LOCK (proc_queue_lock);
            for (proc=proc_queue; proc; proc = proc->next ) {
                if ( !proc->ready && !count_running_fds (proc) ) {
                    set_process_ready (proc);
                }
                if (c && proc->ready && proc->ctx == c)
                    hang = 0;
                if ( !proc->ready )
                    any = 1;
            }
            UNLOCK (proc_queue_lock);
            if (!any)
                hang = 0;
        }
        /* fixme: we should check here for hanging processes */

        if (hang)
            run_idle ();
    } while (hang && !c->cancel );
    c->cancel = 0; /* fixme: fix all functions, to return a cancel error */
    return c;
}



/*
 * We use this function to do the select stuff for all running
 * gpgs.  A future version might provide a facility to delegate
 * those selects to the GDK select stuff.
 * This function must be called only by one thread!!
 * Returns: 0 = nothing to run
 *          1 = did run something 
 */

static int
do_select ( void )
{
    int i, n;
    int any=0;
    
    n = _gpgme_io_select ( fd_table, fd_table_size );
    if ( n <= 0 ) 
        return 0; /* error or timeout */

    for (i=0; i < fd_table_size && n; i++ ) {
        if ( fd_table[i].fd != -1 && fd_table[i].signaled 
             && !fd_table[i].frozen ) {
            struct wait_item_s *q;

            assert (n);
            n--;
            
            q = fd_table[i].opaque;
            assert ( q );
            assert ( q->proc );
            assert ( !q->ready );
            any = 1;
            if ( q->handler (q->handler_value,
                             q->proc->pid, fd_table[i].fd ) ) {
                DEBUG2 ("setting fd %d (q=%p) ready", fd_table[i].fd, q );
                q->ready = 1;
                /* free the table entry*/
                LOCK (fd_table_lock);
                fd_table[i].for_read = 0;
                fd_table[i].for_write = 0;
                fd_table[i].fd = -1;
                fd_table[i].opaque = NULL;
                UNLOCK (fd_table_lock);
            }
        }
    }
    
    return any;
}



/* 
 * called by rungpg.c to register something for select()
 */
GpgmeError
_gpgme_register_pipe_handler ( void *opaque, 
                              int (*handler)(void*,int,int),
                              void *handler_value,
                              int pid, int fd, int inbound )
{
    GpgmeCtx ctx = opaque;
    struct wait_item_s *q;
    struct proc_s *proc;
    int i;

    assert (opaque);
    assert (handler);

    /* Allocate a structure to hold info about the handler */
    q = xtrycalloc ( 1, sizeof *q );
    if ( !q )
        return mk_error (Out_Of_Core);
    q->inbound = inbound;
    q->handler = handler;
    q->handler_value = handler_value;

    /* Put this into the process queue */
    LOCK (proc_queue_lock);
    for (proc=proc_queue; proc && proc->pid != pid; proc = proc->next)
        ;
    if (!proc) { /* a new process */
        proc = xtrycalloc ( 1, sizeof *proc );
        if (!proc) {
            UNLOCK (proc_queue_lock);
            return mk_error (Out_Of_Core);
        }
        proc->pid = pid;
        proc->ctx = ctx;
        proc->next = proc_queue;
        proc_queue = proc;
    }
    assert (proc->ctx == ctx);
    q->proc = proc;
    q->next = proc->handler_list;
    proc->handler_list = q;
    UNLOCK (proc_queue_lock);
    
    LOCK (fd_table_lock);
 again:  
    for (i=0; i < fd_table_size; i++ ) {
        if ( fd_table[i].fd == -1 ) {
            fd_table[i].fd = fd;
            fd_table[i].for_read = inbound;    
            fd_table[i].for_write = !inbound;    
            fd_table[i].signaled = 0;
            fd_table[i].frozen = 0;
            fd_table[i].opaque = q;
            UNLOCK (fd_table_lock);
            return 0;
        }
    }
    if ( fd_table_size < 50 ) {
        /* FIXME: We have to wait until there are no other readers of the 
         * table, i.e that the io_select is not active in another thread */
        struct io_select_fd_s *tmp;

        tmp = xtryrealloc ( fd_table, (fd_table_size + 10) * sizeof *tmp );
        if ( tmp ) {
            for (i=0; i < 10; i++ )
                tmp[fd_table_size+i].fd = -1;
            fd_table_size += i;
            fd_table = tmp;
            goto again;
        }
    }

    UNLOCK (fd_table_lock);
    xfree (q);
    /* FIXME: remove the proc table entry */
    return mk_error (Too_Many_Procs);
}


void
_gpgme_freeze_fd ( int fd )
{
    int i;

    LOCK (fd_table_lock);
    for (i=0; i < fd_table_size; i++ ) {
        if ( fd_table[i].fd == fd ) {
            struct wait_item_s *q;

            fd_table[i].frozen = 1;
            if ( (q=fd_table[i].opaque) )
                q->frozen = 1;
            DEBUG2 ("fd %d frozen (q=%p)", fd, q );
            break;
        }
    }
    UNLOCK (fd_table_lock);
}

void
_gpgme_thaw_fd ( int fd )
{
    int i;

    LOCK (fd_table_lock);
    for (i=0; i < fd_table_size; i++ ) {
        if ( fd_table[i].fd == fd ) {
            struct wait_item_s *q;

            fd_table[i].frozen = 0;
            if ( (q=fd_table[i].opaque) )
                q->frozen = 0;
            DEBUG2 ("fd %d thawed (q=%p)", fd, q );
            break;
        }
    }
    UNLOCK (fd_table_lock);
}


/**
 * gpgme_register_idle:
 * @fnc: Callers idle function
 * 
 * Register a function with GPGME called by GPGME whenever it feels
 * that is is idle.  NULL may be used to remove this function.
 **/
void
gpgme_register_idle ( void (*fnc)(void) )
{
    idle_function = fnc;
}


static void
run_idle ()
{
    _gpgme_gpg_housecleaning ();
    if (idle_function)
        idle_function ();
}

