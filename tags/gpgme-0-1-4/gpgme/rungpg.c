/* rungpg.c 
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
#include <signal.h>
#include <fcntl.h>
#include "unistd.h"

#include "gpgme.h"
#include "util.h"
#include "ops.h"
#include "wait.h"
#include "rungpg.h"
#include "context.h"  /*temp hack until we have GpmeData methods to do I/O */
#include "io.h"

#include "status-table.h"


/* This type is used to build a list of gpg arguments and
 * data sources/sinks */
struct arg_and_data_s {
    struct arg_and_data_s *next;
    GpgmeData data;  /* If this is not NULL .. */
    int dup_to;
    int print_fd;    /* print the fd number and not the special form of it */
    char arg[1];     /* .. this is used */
};

struct fd_data_map_s {
    GpgmeData data;
    int inbound;  /* true if this is used for reading from gpg */
    int dup_to;
    int fd;       /* the fd to use */
    int peer_fd;  /* the outher side of the pipe */
};


struct gpg_object_s {
    struct arg_and_data_s *arglist;
    struct arg_and_data_s **argtail;
    int arg_error;  

    struct {
        int fd[2];  
        size_t bufsize;
        char *buffer;
        size_t readpos;
        int eof;
        GpgStatusHandler fnc;
        void *fnc_value;
    } status;

    /* This is a kludge - see the comment at gpg_colon_line_handler */
    struct {
        int fd[2];  
        size_t bufsize;
        char *buffer;
        size_t readpos;
        int eof;
        GpgColonLineHandler fnc;  /* this indicate use of this structrue */
        void *fnc_value;
    } colon;

    char **argv;  
    struct fd_data_map_s *fd_data_map;

    int pid; /* we can't use pid_t because we don't use it in Windoze */

    int running;
    int exit_status;
    int exit_signal;
    
    /* stuff needed for pipemode */
    struct {
        int used;
        int active;
        GpgmeData sig;
        GpgmeData text;
        int stream_started;
    } pm;

    /* stuff needed for interactive (command) mode */
    struct {
        int used;
        int fd;
        GpgmeData cb_data;   /* hack to get init the above fd later */
        GpgStatusCode code;  /* last code */
        char *keyword;       /* what has been requested (malloced) */
        GpgCommandHandler fnc; 
        void *fnc_value;
    } cmd;
};

static void kill_gpg ( GpgObject gpg );
static void free_argv ( char **argv );
static void free_fd_data_map ( struct fd_data_map_s *fd_data_map );

static int gpg_inbound_handler ( void *opaque, int pid, int fd );
static int gpg_outbound_handler ( void *opaque, int pid, int fd );

static int gpg_status_handler ( void *opaque, int pid, int fd );
static GpgmeError read_status ( GpgObject gpg );

static int gpg_colon_line_handler ( void *opaque, int pid, int fd );
static GpgmeError read_colon_line ( GpgObject gpg );

static int pipemode_cb ( void *opaque,
                         char *buffer, size_t length, size_t *nread );
static int command_cb ( void *opaque,
                        char *buffer, size_t length, size_t *nread );



GpgmeError
_gpgme_gpg_new ( GpgObject *r_gpg )
{
    GpgObject gpg;
    int rc = 0;

    gpg = xtrycalloc ( 1, sizeof *gpg );
    if ( !gpg ) {
        rc = mk_error (Out_Of_Core);
        goto leave;
    }
    gpg->argtail = &gpg->arglist;

    gpg->status.fd[0] = -1;
    gpg->status.fd[1] = -1;
    gpg->colon.fd[0] = -1;
    gpg->colon.fd[1] = -1;
    gpg->cmd.fd = -1;

    /* allocate the read buffer for the status pipe */
    gpg->status.bufsize = 1024;
    gpg->status.readpos = 0;
    gpg->status.buffer = xtrymalloc (gpg->status.bufsize);
    if (!gpg->status.buffer) {
        rc = mk_error (Out_Of_Core);
        goto leave;
    }
    /* In any case we need a status pipe - create it right here  and
     * don't handle it with our generic GpgmeData mechanism */
    if (_gpgme_io_pipe (gpg->status.fd, 1) == -1) {
        rc = mk_error (Pipe_Error);
        goto leave;
    }
    gpg->status.eof = 0;
    _gpgme_gpg_add_arg ( gpg, "--status-fd" );
    {
        char buf[25];
        sprintf ( buf, "%d", gpg->status.fd[1]);
        _gpgme_gpg_add_arg ( gpg, buf );
    }
    _gpgme_gpg_add_arg ( gpg, "--no-tty" );


 leave:
    if (rc) {
        _gpgme_gpg_release (gpg);
        *r_gpg = NULL;
    }
    else
        *r_gpg = gpg;
    return rc;
}


void
_gpgme_gpg_release ( GpgObject gpg )
{
    if ( !gpg )
        return;
    xfree (gpg->status.buffer);
    xfree (gpg->colon.buffer);
    if ( gpg->argv )
        free_argv (gpg->argv);
    xfree (gpg->cmd.keyword);

  #if 0
    /* fixme: We need a way to communicate back closed fds, so that we
     * don't do it a second time.  One way to do it is by using a global
     * table of open fds associated with gpg objects - but this requires
     * additional locking. */
    if (gpg->status.fd[0] != -1 )
        _gpgme_io_close (gpg->status.fd[0]);
    if (gpg->status.fd[1] != -1 )
        _gpgme_io_close (gpg->status.fd[1]);
    if (gpg->colon.fd[0] != -1 )
        _gpgme_io_close (gpg->colon.fd[0]);
    if (gpg->colon.fd[1] != -1 )
        _gpgme_io_close (gpg->colon.fd[1]);
  #endif
    free_fd_data_map (gpg->fd_data_map);
    kill_gpg (gpg); /* fixme: should be done asyncronously */
    xfree (gpg);
}

static void
kill_gpg ( GpgObject gpg )
{
  #if 0
    if ( gpg->running ) {
        /* still running? Must send a killer */
        kill ( gpg->pid, SIGTERM);
        sleep (2);
        if ( !waitpid (gpg->pid, NULL, WNOHANG) ) {
            /* pay the murderer better and then forget about it */
            kill (gpg->pid, SIGKILL);
        }
        gpg->running = 0;
    }
  #endif
}

void
_gpgme_gpg_enable_pipemode ( GpgObject gpg )
{
    gpg->pm.used = 1;
    assert ( !gpg->pm.sig );
    assert ( !gpg->pm.text );
}
    
GpgmeError
_gpgme_gpg_add_arg ( GpgObject gpg, const char *arg )
{
    struct arg_and_data_s *a;

    assert (gpg);
    assert (arg);

    if (gpg->pm.active)
        return 0;

    a = xtrymalloc ( sizeof *a + strlen (arg) );
    if ( !a ) {
        gpg->arg_error = 1;
        return mk_error(Out_Of_Core);
    }
    a->next = NULL;
    a->data = NULL;
    a->dup_to = -1;
    strcpy ( a->arg, arg );
    *gpg->argtail = a;
    gpg->argtail = &a->next;
    return 0;
}

GpgmeError
_gpgme_gpg_add_data ( GpgObject gpg, GpgmeData data, int dup_to )
{
    struct arg_and_data_s *a;

    assert (gpg);
    assert (data);
    if (gpg->pm.active)
        return 0;

    a = xtrymalloc ( sizeof *a - 1 );
    if ( !a ) {
        gpg->arg_error = 1;
        return mk_error(Out_Of_Core);
    }
    a->next = NULL;
    a->data = data;
    if ( dup_to == -2 ) {
        a->print_fd = 1;
        a->dup_to = -1;
    }
    else {
        a->print_fd = 0;
        a->dup_to = dup_to;
    }
    *gpg->argtail = a;
    gpg->argtail = &a->next;
    return 0;
}

GpgmeError
_gpgme_gpg_add_pm_data ( GpgObject gpg, GpgmeData data, int what )
{
    GpgmeError rc=0;

    assert ( gpg->pm.used );
    
    if ( !what ) {
        /* the signature */
        assert ( !gpg->pm.sig );
        gpg->pm.sig = data;
    }
    else if (what == 1) {
        /* the signed data */
        assert ( !gpg->pm.text );
        gpg->pm.text = data;
    }
    else {
        assert (0);
    }

    if ( gpg->pm.sig && gpg->pm.text ) {
        if ( !gpg->pm.active ) {
            /* create the callback handler and connect it to stdin */
            GpgmeData tmp;
            
            rc = gpgme_data_new_with_read_cb ( &tmp, pipemode_cb, gpg );
            if (!rc )
                rc = _gpgme_gpg_add_data (gpg, tmp, 0);
        }
        if ( !rc ) {
            /* here we can reset the handler stuff */
            gpg->pm.stream_started = 0;
        }
    }

    return rc;
}

/*
 * Note, that the status_handler is allowed to modifiy the args value
 */
void
_gpgme_gpg_set_status_handler ( GpgObject gpg,
                                GpgStatusHandler fnc, void *fnc_value ) 
{
    assert (gpg);
    if (gpg->pm.active)
        return;

    gpg->status.fnc = fnc;
    gpg->status.fnc_value = fnc_value;
}

/* Kludge to process --with-colon output */
GpgmeError
_gpgme_gpg_set_colon_line_handler ( GpgObject gpg,
                                    GpgColonLineHandler fnc, void *fnc_value ) 
{
    assert (gpg);
    if (gpg->pm.active)
        return 0;

    gpg->colon.bufsize = 1024;
    gpg->colon.readpos = 0;
    gpg->colon.buffer = xtrymalloc (gpg->colon.bufsize);
    if (!gpg->colon.buffer) {
        return mk_error (Out_Of_Core);
    }
    if (_gpgme_io_pipe (gpg->colon.fd, 1) == -1) {
        xfree (gpg->colon.buffer); gpg->colon.buffer = NULL;
        return mk_error (Pipe_Error);
    }
    gpg->colon.eof = 0;
    gpg->colon.fnc = fnc;
    gpg->colon.fnc_value = fnc_value;
    return 0;
}


/* 
 * The Fnc will be called to get a value for one of the commands with
 * a key KEY.  If the Code pssed to FNC is 0, the function may release
 * resources associated with the returned value from another call.  To
 * match such a second call to a first call, the returned value from
 * the first call is passed as keyword.
 */

GpgmeError
_gpgme_gpg_set_command_handler ( GpgObject gpg,
                                 GpgCommandHandler fnc, void *fnc_value ) 
{
    GpgmeData tmp;
    GpgmeError err;

    assert (gpg);
    if (gpg->pm.active)
        return 0;

    err = gpgme_data_new_with_read_cb ( &tmp, command_cb, gpg );
    if (err)
        return err;
        
    _gpgme_gpg_add_arg ( gpg, "--command-fd" );
    _gpgme_gpg_add_data (gpg, tmp, -2);
    gpg->cmd.cb_data = tmp;
    gpg->cmd.fnc = fnc;
    gpg->cmd.fnc_value = fnc_value;
    gpg->cmd.used = 1;
    return 0;
}


static void
free_argv ( char **argv )
{
    int i;

    for (i=0; argv[i]; i++ )
        xfree (argv[i]);
    xfree (argv);
}

static void
free_fd_data_map ( struct fd_data_map_s *fd_data_map )
{
    int i;

    if ( !fd_data_map )
        return;

    for (i=0; fd_data_map[i].data; i++ ) {
#if 0 /* fixme -> see gpg_release */
        if ( fd_data_map[i].fd != -1 )
            _gpgme_io_close (fd_data_map[i].fd);
        if ( fd_data_map[i].peer_fd != -1 )
            _gpgme_io_close (fd_data_map[i].peer_fd);
#endif
        /* don't release data because this is only a reference */
    }
    xfree (fd_data_map);
}


static GpgmeError
build_argv ( GpgObject gpg )
{
    struct arg_and_data_s *a;
    struct fd_data_map_s *fd_data_map;
    size_t datac=0, argc=0;  
    char **argv;
    int need_special = 0;
    int use_agent = !!getenv ("GPG_AGENT_INFO");
       
    if ( gpg->argv ) {
        free_argv ( gpg->argv );
        gpg->argv = NULL;
    }
    if (gpg->fd_data_map) {
        free_fd_data_map (gpg->fd_data_map);
        gpg->fd_data_map = NULL;
    }

    argc++; /* for argv[0] */
    for ( a=gpg->arglist; a; a = a->next ) {
        argc++;
        if (a->data) {
            /*fprintf (stderr, "build_argv: data\n" );*/
            datac++;
            if ( a->dup_to == -1 && !a->print_fd )
                need_special = 1;
        }
        else {
            /*   fprintf (stderr, "build_argv: arg=`%s'\n", a->arg );*/
        }
    }
    if ( need_special )
        argc++;
    if (use_agent)
        argc++;
    if (!gpg->cmd.used)
        argc++;

    argv = xtrycalloc ( argc+1, sizeof *argv );
    if (!argv)
        return mk_error (Out_Of_Core);
    fd_data_map = xtrycalloc ( datac+1, sizeof *fd_data_map );
    if (!fd_data_map) {
        free_argv (argv);
        return mk_error (Out_Of_Core);
    }

    argc = datac = 0;
    argv[argc] = xtrystrdup ( "gpg" ); /* argv[0] */
    if (!argv[argc]) {
        xfree (fd_data_map);
        free_argv (argv);
        return mk_error (Out_Of_Core);
    }
    argc++;
    if ( need_special ) {
        argv[argc] = xtrystrdup ( "--enable-special-filenames" );
        if (!argv[argc]) {
            xfree (fd_data_map);
            free_argv (argv);
            return mk_error (Out_Of_Core);
        }
        argc++;
    }
    if ( use_agent ) {
        argv[argc] = xtrystrdup ( "--use-agent" );
        if (!argv[argc]) {
            xfree (fd_data_map);
            free_argv (argv);
            return mk_error (Out_Of_Core);
        }
        argc++;
    }
    if ( !gpg->cmd.used ) {
        argv[argc] = xtrystrdup ( "--batch" );
        if (!argv[argc]) {
            xfree (fd_data_map);
            free_argv (argv);
            return mk_error (Out_Of_Core);
        }
        argc++;
    }
    for ( a=gpg->arglist; a; a = a->next ) {
        if ( a->data ) {
            switch ( _gpgme_data_get_mode (a->data) ) {
              case GPGME_DATA_MODE_NONE:
              case GPGME_DATA_MODE_INOUT:
                xfree (fd_data_map);
                free_argv (argv);
                return mk_error (Invalid_Mode);
              case GPGME_DATA_MODE_IN:
                /* create a pipe to read from gpg */
                fd_data_map[datac].inbound = 1;
                break;
              case GPGME_DATA_MODE_OUT:
                /* create a pipe to pass it down to gpg */
                fd_data_map[datac].inbound = 0;
                break;
            }

            switch ( gpgme_data_get_type (a->data) ) {
              case GPGME_DATA_TYPE_NONE:
                if ( fd_data_map[datac].inbound )
                    break;  /* allowed */
                xfree (fd_data_map);
                free_argv (argv);
                return mk_error (Invalid_Type);
              case GPGME_DATA_TYPE_MEM:
              case GPGME_DATA_TYPE_CB:
                break;
              case GPGME_DATA_TYPE_FD:
              case GPGME_DATA_TYPE_FILE:
                xfree (fd_data_map);
                free_argv (argv);
                return mk_error (Not_Implemented);
            }
  
            /* create a pipe */
            {   
                int fds[2];
                
                if (_gpgme_io_pipe (fds, fd_data_map[datac].inbound?1:0 )
                    == -1) {
                    xfree (fd_data_map);
                    free_argv (argv);
                    return mk_error (Pipe_Error);
                }
                /* if the data_type is FD, we have to do a dup2 here */
                if (fd_data_map[datac].inbound) {
                    fd_data_map[datac].fd       = fds[0];
                    fd_data_map[datac].peer_fd  = fds[1];
                }
                else {
                    fd_data_map[datac].fd       = fds[1];
                    fd_data_map[datac].peer_fd  = fds[0];
                }
            }

            /* Hack to get hands on the fd later */
            if ( gpg->cmd.used && gpg->cmd.cb_data == a->data ) {
                assert (gpg->cmd.fd == -1);
                gpg->cmd.fd = fd_data_map[datac].fd;
            }

            fd_data_map[datac].data = a->data;
            fd_data_map[datac].dup_to = a->dup_to;
            if ( a->dup_to == -1 ) {
                argv[argc] = xtrymalloc ( 25 );
                if (!argv[argc]) {
                    xfree (fd_data_map);
                    free_argv (argv);
                    return mk_error (Out_Of_Core);
                }
                sprintf ( argv[argc], 
                          a->print_fd? "%d" : "-&%d",
                          fd_data_map[datac].peer_fd );
                argc++;
            }
            datac++;
        }
        else {
            argv[argc] = xtrystrdup ( a->arg );
            if (!argv[argc]) {
                xfree (fd_data_map);
                free_argv (argv);
                return mk_error (Out_Of_Core);
            }
            argc++;
        }
    }

    gpg->argv = argv;
    gpg->fd_data_map = fd_data_map;
    return 0;
}

GpgmeError
_gpgme_gpg_spawn( GpgObject gpg, void *opaque )
{
    int rc;
    int i, n;
    int pid;
    struct spawn_fd_item_s *fd_child_list, *fd_parent_list;

    if ( !gpg )
        return mk_error (Invalid_Value);

    /* Kludge, so that we don't need to check the return code of
     * all the gpgme_gpg_add_arg().  we bail out here instead */
    if ( gpg->arg_error )
        return mk_error (Out_Of_Core);

    if (gpg->pm.active)
        return 0;

    rc = build_argv ( gpg );
    if ( rc )
        return rc;

    n = 4; /* status fd, 2*colon_fd and end of list */
    for (i=0; gpg->fd_data_map[i].data; i++ ) 
        n += 2;
    fd_child_list = xtrycalloc ( n+n, sizeof *fd_child_list );
    if (!fd_child_list)
        return mk_error (Out_Of_Core);
    fd_parent_list = fd_child_list + n;

    /* build the fd list for the child */
    n=0;
    fd_child_list[n].fd = gpg->status.fd[0]; 
    fd_child_list[n].dup_to = -1;
    n++;
    if ( gpg->colon.fnc ) {
        fd_child_list[n].fd = gpg->colon.fd[0];
        fd_child_list[n].dup_to = -1;
        n++;
        fd_child_list[n].fd = gpg->colon.fd[1]; 
        fd_child_list[n].dup_to = 1; /* dup to stdout */
        n++;
    }
    for (i=0; gpg->fd_data_map[i].data; i++ ) {
        fd_child_list[n].fd = gpg->fd_data_map[i].fd;
        fd_child_list[n].dup_to = -1;
        n++;
        if (gpg->fd_data_map[i].dup_to != -1) {
            fd_child_list[n].fd = gpg->fd_data_map[i].peer_fd;
            fd_child_list[n].dup_to = gpg->fd_data_map[i].dup_to;
            n++;
        }
    }
    fd_child_list[n].fd = -1;
    fd_child_list[n].dup_to = -1;

    /* build the fd list for the parent */
    n=0;
    if ( gpg->status.fd[1] != -1 ) {
        fd_parent_list[n].fd = gpg->status.fd[1];
        fd_parent_list[n].dup_to = -1;
        n++;
        gpg->status.fd[1] = -1;
    }
    if ( gpg->colon.fd[1] != -1 ) {
        fd_parent_list[n].fd = gpg->colon.fd[1];
        fd_parent_list[n].dup_to = -1;
        n++;
        gpg->colon.fd[1] = -1;
    }
    for (i=0; gpg->fd_data_map[i].data; i++ ) {
        fd_parent_list[n].fd = gpg->fd_data_map[i].peer_fd;
        fd_parent_list[n].dup_to = -1;
        n++;
        gpg->fd_data_map[i].peer_fd = -1;
    }        
    fd_parent_list[n].fd = -1;
    fd_parent_list[n].dup_to = -1;


    pid = _gpgme_io_spawn (GPG_PATH, gpg->argv, fd_child_list, fd_parent_list);
    xfree (fd_child_list);
    if (pid == -1) {
        return mk_error (Exec_Error);
    }

    gpg->pid = pid;
    if (gpg->pm.used)
        gpg->pm.active = 1;

    /*_gpgme_register_term_handler ( closure, closure_value, pid );*/

    if ( _gpgme_register_pipe_handler ( opaque, gpg_status_handler,
                                        gpg, pid, gpg->status.fd[0], 1 ) ) {
        /* FIXME: kill the child */
        return mk_error (General_Error);

    }

    if ( gpg->colon.fnc ) {
        assert ( gpg->colon.fd[0] != -1 );
        if ( _gpgme_register_pipe_handler ( opaque, gpg_colon_line_handler,
                                            gpg, pid, gpg->colon.fd[0], 1 ) ) {
            /* FIXME: kill the child */
            return mk_error (General_Error);
            
        }
    }

    for (i=0; gpg->fd_data_map[i].data; i++ ) {
        /* Due to problems with select and write we set outbound pipes
         * to non-blocking */
        if (!gpg->fd_data_map[i].inbound) {
            _gpgme_io_set_nonblocking (gpg->fd_data_map[i].fd);
        }

        if ( _gpgme_register_pipe_handler (
                 opaque, 
                 gpg->fd_data_map[i].inbound?
                       gpg_inbound_handler:gpg_outbound_handler,
                 gpg->fd_data_map[i].data,
                 pid, gpg->fd_data_map[i].fd,
                 gpg->fd_data_map[i].inbound )
           ) {
            /* FIXME: kill the child */
            return mk_error (General_Error);
        }
    }

    if ( gpg->cmd.used )
        _gpgme_freeze_fd ( gpg->cmd.fd );

    /* fixme: check what data we can release here */
    
    gpg->running = 1;
    return 0;
}


static int
gpg_inbound_handler ( void *opaque, int pid, int fd )
{
    GpgmeData dh = opaque;
    GpgmeError err;
    int nread;
    char buf[200];

    assert ( _gpgme_data_get_mode (dh) == GPGME_DATA_MODE_IN );

    nread = _gpgme_io_read (fd, buf, 200 );
    if ( nread < 0 ) {
        fprintf (stderr, "read_mem_data: read failed on fd %d (n=%d): %s\n",
                 fd, nread, strerror (errno) );
        return 1;
    }
    else if (!nread)
        return 1; /* eof */

    /* We could improve this with a GpgmeData function which takes
     * the read function or provides a memory area for writing to it.
     */
    
    err = _gpgme_data_append ( dh, buf, nread );
    if ( err ) {
        fprintf (stderr, "_gpgme_append_data failed: %s\n",
                 gpgme_strerror(err));
        /* Fixme: we should close the pipe or read it to /dev/null in
         * this case. Returnin EOF is not sufficient */
        return 1;
    }

    return 0;
}


static int
write_mem_data ( GpgmeData dh, int fd )
{
    size_t nbytes;
    int  nwritten; 

    nbytes = dh->len - dh->readpos;
    if ( !nbytes ) {
        _gpgme_io_close (fd);
        return 1;
    }
    
    /* FIXME: Arggg, the pipe blocks on large write request, although
     * select told us that it is okay to write - need to figure out
     * why this happens?  Stevens says nothing about this problem (or
     * is it my Linux kernel 2.4.0test1)
     * To avoid that we have set the pipe to nonblocking.
     */

    nwritten = _gpgme_io_write ( fd, dh->data+dh->readpos, nbytes );
    if (nwritten == -1 && errno == EAGAIN )
        return 0;
    if ( nwritten < 1 ) {
        fprintf (stderr, "write_mem_data(%d): write failed (n=%d): %s\n",
                 fd, nwritten, strerror (errno) );
        _gpgme_io_close (fd);
        return 1;
    }

    dh->readpos += nwritten;
    return 0;
}

static int
write_cb_data ( GpgmeData dh, int fd )
{
    size_t nbytes;
    int  err, nwritten; 
    char buffer[512];

    err = gpgme_data_read ( dh, buffer, DIM(buffer), &nbytes );
    if (err == GPGME_EOF) {
        _gpgme_io_close (fd);
        return 1;
    }
    
    nwritten = _gpgme_io_write ( fd, buffer, nbytes );
    if (nwritten == -1 && errno == EAGAIN )
        return 0;
    if ( nwritten < 1 ) {
        fprintf (stderr, "write_cb_data(%d): write failed (n=%d): %s\n",
                 fd, nwritten, strerror (errno) );
        _gpgme_io_close (fd);
        return 1;
    }

    if ( nwritten < nbytes ) {
        /* ugly, ugly: It does currently only for for MEM type data */
        if ( _gpgme_data_unread (dh, buffer + nwritten, nbytes - nwritten ) )
            fprintf (stderr, "wite_cb_data: unread of %d bytes failed\n",
                     nbytes - nwritten );
        _gpgme_io_close (fd);
        return 1;
    }

    return 0;
}


static int
gpg_outbound_handler ( void *opaque, int pid, int fd )
{
    GpgmeData dh = opaque;

    assert ( _gpgme_data_get_mode (dh) == GPGME_DATA_MODE_OUT );
    switch ( gpgme_data_get_type (dh) ) {
      case GPGME_DATA_TYPE_MEM:
        if ( write_mem_data ( dh, fd ) )
            return 1; /* ready */
        break;
      case GPGME_DATA_TYPE_CB:
        if (write_cb_data (dh, fd))
            return 1; /* ready */
        break;
      default:
        assert (0);
    }

    return 0;
}



static int
gpg_status_handler ( void *opaque, int pid, int fd )
{
    GpgObject gpg = opaque;
    int rc = 0;

    assert ( fd == gpg->status.fd[0] );
    rc = read_status ( gpg );
    if ( rc ) {
        fprintf (stderr, "gpg_handler: read_status problem %d\n - stop", rc);
        return 1;
    }

    return gpg->status.eof;
}


static int
status_cmp (const void *ap, const void *bp)
{
    const struct status_table_s *a = ap;
    const struct status_table_s *b = bp;

    return strcmp (a->name, b->name);
}



/*
 * Handle the status output of GnuPG.  This function does read entire
 * lines and passes them as C strings to the callback function (we can
 * use C Strings because the status output is always UTF-8 encoded).
 * Of course we have to buffer the lines to cope with long lines
 * e.g. with a large user ID.  Note: We can optimize this to only cope
 * with status line code we know about and skip all other stuff
 * without buffering (i.e. without extending the buffer).  */
static GpgmeError
read_status ( GpgObject gpg )
{
    char *p;
    int nread;
    size_t bufsize = gpg->status.bufsize; 
    char *buffer = gpg->status.buffer;
    size_t readpos = gpg->status.readpos; 

    assert (buffer);
    if (bufsize - readpos < 256) { 
        /* need more room for the read */
        bufsize += 1024;
        buffer = xtryrealloc (buffer, bufsize);
        if ( !buffer ) 
            return mk_error (Out_Of_Core);
    }
    

    nread = _gpgme_io_read ( gpg->status.fd[0],
                             buffer+readpos, bufsize-readpos );
    if (nread == -1)
        return mk_error(Read_Error);

    if (!nread) {
        gpg->status.eof = 1;
        if (gpg->status.fnc)
            gpg->status.fnc ( gpg->status.fnc_value, STATUS_EOF, "" );
        return 0;
    }

    while (nread > 0) {
        for (p = buffer + readpos; nread; nread--, p++) {
            if ( *p == '\n' ) {
                /* (we require that the last line is terminated by a LF) */
                *p = 0;
                /*fprintf (stderr, "read_status: `%s'\n", buffer);*/
                if (!strncmp (buffer, "[GNUPG:] ", 9 )
                    && buffer[9] >= 'A' && buffer[9] <= 'Z' ) {
                    struct status_table_s t, *r;
                    char *rest;

                    rest = strchr (buffer+9, ' ');
                    if ( !rest )
                        rest = p; /* set to an empty string */
                    else
                        *rest++ = 0;
                    
                    t.name = buffer+9;
                    /* (the status table as one extra element) */
                    r = bsearch ( &t, status_table, DIM(status_table)-1,
                                  sizeof t, status_cmp );
                    if ( r ) {
                        if ( gpg->cmd.used
                             && ( r->code == STATUS_GET_BOOL
                                  || r->code == STATUS_GET_LINE
                                  || r->code == STATUS_GET_HIDDEN )) {
                            gpg->cmd.code = r->code;
                            xfree (gpg->cmd.keyword);
                            gpg->cmd.keyword = xtrystrdup (rest);
                            if ( !gpg->cmd.keyword )
                                return mk_error (Out_Of_Core);
                            /* this should be the last thing we have received
                             * and the next thing will be that the command
                             * handler does it action */
                            if ( nread > 1 )
                                fprintf (stderr, "** ERROR, unxpected data in"
                                         " read_status\n" );
                            _gpgme_thaw_fd (gpg->cmd.fd);
                        }
                        else if ( gpg->status.fnc ) {
                            gpg->status.fnc ( gpg->status.fnc_value, 
                                              r->code, rest);
                        }
                    }
                    if ( r->code == STATUS_END_STREAM ) {
                        /* _gpgme_freeze_fd ( ? );*/
                    }
                }
                /* To reuse the buffer for the next line we have to
                 * shift the remaining data to the buffer start and
                 * restart the loop Hmmm: We can optimize this
                 * function by looking forward in the buffer to see
                 * whether a second complete line is available and in
                 * this case avoid the memmove for this line.  */
                nread--; p++;
                if (nread)
                    memmove (buffer, p, nread);
                readpos = 0;
                break; /* the for loop */
            }
            else
                readpos++;
        }
    } 

    /* Update the gpg object.  */
    gpg->status.bufsize = bufsize;
    gpg->status.buffer = buffer;
    gpg->status.readpos = readpos;
    return 0;
}


/*
 * This colonline handler thing is not the clean way to do it.
 * It might be better to enhance the GpgmeData object to act as
 * a wrapper for a callback.  Same goes for the status thing.
 * For now we use this thing here becuase it is easier to implement.
 */
static int
gpg_colon_line_handler ( void *opaque, int pid, int fd )
{
    GpgObject gpg = opaque;
    GpgmeError rc = 0;

    assert ( fd == gpg->colon.fd[0] );
    rc = read_colon_line ( gpg );
    if ( rc ) {
        fprintf (stderr, "gpg_colon_line_handler: "
                 "read problem %d\n - stop", rc);
        return 1;
    }

    return gpg->status.eof;
}

static GpgmeError
read_colon_line ( GpgObject gpg )
{
    char *p;
    int nread;
    size_t bufsize = gpg->colon.bufsize; 
    char *buffer = gpg->colon.buffer;
    size_t readpos = gpg->colon.readpos; 

    assert (buffer);
    if (bufsize - readpos < 256) { 
        /* need more room for the read */
        bufsize += 1024;
        buffer = xtryrealloc (buffer, bufsize);
        if ( !buffer ) 
            return mk_error (Out_Of_Core);
    }
    

    nread = _gpgme_io_read ( gpg->colon.fd[0],
                             buffer+readpos, bufsize-readpos );
    if (nread == -1)
        return mk_error(Read_Error);

    if (!nread) {
        gpg->colon.eof = 1;
        assert (gpg->colon.fnc);
        gpg->colon.fnc ( gpg->colon.fnc_value, NULL );
        return 0;
    }

    while (nread > 0) {
        for (p = buffer + readpos; nread; nread--, p++) {
            if ( *p == '\n' ) {
                /* (we require that the last line is terminated by a
                 * LF) and we skip empty lines.  Note: we use UTF8
                 * encoding and escaping of special characters
                 * We require at least one colon to cope with
                 * some other printed information.
                 */
                *p = 0;
                if ( *buffer && strchr (buffer, ':') ) {
                    assert (gpg->colon.fnc);
                    gpg->colon.fnc ( gpg->colon.fnc_value, buffer );
                }
            
                /* To reuse the buffer for the next line we have to
                 * shift the remaining data to the buffer start and
                 * restart the loop Hmmm: We can optimize this
                 * function by looking forward in the buffer to see
                 * whether a second complete line is available and in
                 * this case avoid the memmove for this line.  */
                nread--; p++;
                if (nread)
                    memmove (buffer, p, nread);
                readpos = 0;
                break; /* the for loop */
            }
            else
                readpos++;
        }
    } 
    
    /* Update the gpg object.  */
    gpg->colon.bufsize = bufsize;
    gpg->colon.buffer  = buffer;
    gpg->colon.readpos = readpos;
    return 0;
}

static GpgmeError
pipemode_copy (char *buffer, size_t length, size_t *nread, GpgmeData data )
{
    GpgmeError err;
    int nbytes;
    char tmp[1000], *s, *d;

    /* we can optimize this whole thing but for now we just
     * return after each escape character */
    if (length > 990)
        length = 990;

    err = gpgme_data_read ( data, tmp, length, &nbytes );
    if (err)
        return err;
    for (s=tmp, d=buffer; nbytes; s++, nbytes--) {
        *d++ = *s;
        if (*s == '@' ) {
            *d++ = '@';
            break;
        }
    }
    *nread = d - buffer;
    return 0;
}


static int
pipemode_cb ( void *opaque, char *buffer, size_t length, size_t *nread )
{
    GpgObject gpg = opaque;
    GpgmeError err;

    if ( !buffer || !length || !nread )
        return 0; /* those values are reserved for extensions */
    *nread =0;
    if ( !gpg->pm.stream_started ) {
        assert (length > 4 );
        strcpy (buffer, "@<@B" );
        *nread = 4;
        gpg->pm.stream_started = 1;
    }
    else if ( gpg->pm.sig ) {
        err = pipemode_copy ( buffer, length, nread, gpg->pm.sig );
        if ( err == GPGME_EOF ) {
            gpg->pm.sig = NULL;
            assert (length > 4 );
            strcpy (buffer, "@t" );
            *nread = 2;
        }
        else if (err) {
            fprintf (stderr, "** pipemode_cb: copy sig failed: %s\n",
                     gpgme_strerror (err) );
            return -1;
        }
    }
    else if ( gpg->pm.text ) {
        err = pipemode_copy ( buffer, length, nread, gpg->pm.text );
        if ( err == GPGME_EOF ) {
            gpg->pm.text = NULL;
            assert (length > 4 );
            strcpy (buffer, "@.@>" );
            *nread = 4;
        }
        else if (err) {
            fprintf (stderr, "** pipemode_cb: copy data failed: %s\n",
                     gpgme_strerror (err) );
            return -1;
        }
    }
    else {
        return 0; /* eof */
    }

    return 0;
}


/* 
 * Here we handle --command-fd.  This works closely together with
 * the status handler.  
 */

static int
command_cb ( void *opaque, char *buffer, size_t length, size_t *nread )
{
    GpgObject gpg = opaque;
    const char *value;
    int value_len;

    fprintf (stderr, "** command_cb: enter\n");
    assert (gpg->cmd.used);
    if ( !buffer || !length || !nread )
        return 0; /* those values are reserved for extensions */
    *nread =0;
    if ( !gpg->cmd.code ) {
        fprintf (stderr, "** command_cb: no code\n");
        return -1;
    }
    
    if ( !gpg->cmd.fnc ) {
        fprintf (stderr, "** command_cb: no user cb\n");
        return -1;
    }

    value = gpg->cmd.fnc ( gpg->cmd.fnc_value, 
                           gpg->cmd.code, gpg->cmd.keyword );
    if ( !value ) {
        fprintf (stderr, "** command_cb: no data from user cb\n");
        gpg->cmd.fnc ( gpg->cmd.fnc_value, 0, value);
        return -1;
    }

    value_len = strlen (value);
    if ( value_len+1 > length ) {
        fprintf (stderr, "** command_cb: too much data from user cb\n");
        gpg->cmd.fnc ( gpg->cmd.fnc_value, 0, value);
        return -1;
    }

    memcpy ( buffer, value, value_len );
    if ( !value_len || (value_len && value[value_len-1] != '\n') ) 
        buffer[value_len++] = '\n';
    *nread = value_len;
    
    fprintf (stderr, "** command_cb: leave (wrote `%.*s')\n",
             (int)*nread-1, buffer);
    gpg->cmd.fnc ( gpg->cmd.fnc_value, 0, value);
    gpg->cmd.code = 0;
    /* and sleep again until read_status will wake us up again */
    _gpgme_freeze_fd ( gpg->cmd.fd );
    return 0;
}




