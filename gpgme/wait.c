/* wait.c 
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

#include "util.h"
#include "context.h"
#include "wait.h"

/* Fixme: implement the following stuff to make the code MT safe.
 * To avoid the need to link against a specific threads lib, such
 * an implementation should require the caller to register a function
 * which does this task.
 * enter_crit() and leave_crit() are used to embrace an area of code
 * which should be executed only by one thread at a time.
 * lock_xxxx() and unlock_xxxx()  protect access to an data object.
 *  */
#define enter_crit()    do { } while (0)
#define leave_crit()    do { } while (0)
#define lock_queue()    do { } while (0)
#define unlock_queue()  do { } while (0)

struct wait_queue_item_s {
    struct wait_queue_item_s *next;
    volatile int used; 
    volatile int active;
    int (*handler)(void*,pid_t,int);
    void *handler_value;
    pid_t pid;
    int   fd;  
    int   inbound;       /* this is an inbound data handler fd */

    int exited;
    int exit_status;  
    int exit_signal;

    GpgmeCtx ctx;
};


static struct wait_queue_item_s wait_queue[SIZEOF_WAIT_QUEUE];

static int the_big_select ( void );


static void
init_wait_queue (void)
{
    int i;
    static int initialized = 0;

    if ( initialized )  /* FIXME: This leads to a race */
        return;

    lock_queue ();
    for (i=1; i < SIZEOF_WAIT_QUEUE; i++ )
        wait_queue[i-1].next = &wait_queue[i];
    initialized = 1;
    unlock_queue();
}

static struct wait_queue_item_s *
queue_item_from_context ( GpgmeCtx ctx )
{
    struct wait_queue_item_s *q;

    for (q=wait_queue; q; q = q->next) {
        if ( q->used && q->ctx == ctx )
            return q;
    }
    return NULL;
}


/**
 * gpgme_wait:
 * @c: 
 * @hang: 
 * 
 * Wait for a finished request, if @c is given the function does only
 * wait on a finsihed request for that context, otherwise it will return
 * on any request.  When @hang is true the function will wait, otherwise
 * it will return immediately when there is no pending finished request.
 * 
 * Return value: Context of the finished request or NULL if @hang is false
 *  and no (or the given) request has finished.
 **/
GpgmeCtx 
gpgme_wait ( GpgmeCtx c, int hang )
{
    struct wait_queue_item_s *q;

    init_wait_queue ();
    do {
        if ( !the_big_select() ) {
            int status;

            /* We did no read/write - see whether this process is still
             * alive */
            assert (c); /* !c is not yet implemented */
            q = queue_item_from_context ( c );
            assert (q);
            
            if ( waitpid ( q->pid, &status, WNOHANG ) == q->pid ) {
                q->exited = 1;     
                if ( WIFSIGNALED (status) ) {
                    q->exit_status = 4; /* Need some value here */
                    q->exit_signal = WTERMSIG (status);
                }
                else if ( WIFEXITED (status) ) {
                    q->exit_status = WEXITSTATUS (status);
                }
                else {
                    q->exited++;
                    q->exit_status = 4;
                }
                /* okay, the process has terminated - we are ready */
                hang = 0;
            }
        }
    } while (hang);
    return c;
}



/*
 * We use this function to do the select stuff for all running
 * gpgs.  A future version might provide a facility to delegate
 * those selects to the GDK select stuff.
 * This function must be called only by one thread!!
 * FIXME: The data structures and  algorithms are stupid.
 * Returns: 0 = nothing to run
 *          1 = did run something 
 */

static int
the_big_select ( void )
{
    static fd_set readfds;
    static fd_set writefds;
    struct wait_queue_item_s *q;
    int max_fd, n;
    struct timeval timeout = { 1, 0 }; /* Use a one second timeout */
    
    FD_ZERO ( &readfds );
    FD_ZERO ( &writefds );
    max_fd = 0;
    lock_queue ();
    for ( q = wait_queue; q; q = q->next ) {
        if ( q->used && q->active ) {
            if (q->inbound) {
                assert ( !FD_ISSET ( q->fd, &readfds ) );
                FD_SET ( q->fd, &readfds );
            }
            else {
                assert ( !FD_ISSET ( q->fd, &writefds ) );
                FD_SET ( q->fd, &writefds );
            }
            if ( q->fd > max_fd )
                max_fd = q->fd;
          }
    }
    unlock_queue ();


    n = select ( max_fd+1, &readfds, &writefds, NULL, &timeout );
    if ( n <= 0 ) {
        if ( n && errno != EINTR ) {
            fprintf (stderr, "the_big_select: select failed: %s\n",
                     strerror (errno) );
        }
        return 0;
    }

    /* something has to be done.  Go over the queue and call
     * the handlers */
 restart:
    while ( n ) {
        lock_queue ();
        for ( q = wait_queue; q; q = q->next ) {
            if ( q->used && q->active 
                 && FD_ISSET (q->fd, q->inbound? &readfds : &writefds ) ) {
                FD_CLR (q->fd, q->inbound? &readfds : &writefds );
                assert (n);
                n--;
                unlock_queue ();
                if ( q->handler (q->handler_value, q->pid, q->fd ) )
                    q->active = 0;
                goto restart;
            }
        }
        unlock_queue ();
    }
    return 1;
}



/* 
 * called by rungpg.c to register something for select()
 */
GpgmeError
_gpgme_register_pipe_handler( void *opaque, 
                              int (*handler)(void*,pid_t,int),
                              void *handler_value,
                              pid_t pid, int fd, int inbound )
{
    GpgmeCtx ctx = opaque;
    struct wait_queue_item_s *q;

    init_wait_queue();
    assert (opaque);
    assert (handler);
    
    lock_queue ();
    for ( q = wait_queue; q; q = q->next ) {
        if ( !q->used ) {
            q->used = 1;
            q->active = 0;
            break;
        }
    }
    unlock_queue ();
    if ( !q ) 
        return mk_error (Too_Many_Procs);

    q->fd = fd;
    q->inbound = inbound;
    q->handler = handler;
    q->handler_value = handler_value;
    q->pid = pid;
    q->ctx = ctx;
    
    /* and enable this entry for the next select */
    q->exited = 0;
    q->active = 1;
    return 0;
}

















