/* assuan-defs.c - Internal definitions to Assuan
 *	Copyright (C) 2001, 2002 Free Software Foundation, Inc.
 *
 * This file is part of Assuan.
 *
 * Assuan is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Assuan is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA 
 */

#ifndef ASSUAN_DEFS_H
#define ASSUAN_DEFS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "assuan.h"

#define LINELENGTH ASSUAN_LINELENGTH

struct cmdtbl_s
{
  const char *name;
  int (*handler)(ASSUAN_CONTEXT, char *line);
};

struct assuan_io
{
  /* Routine to read from input_fd.  */
  ssize_t (*read) (ASSUAN_CONTEXT, void *, size_t);
  /* Routine to write to output_fd.  */
  ssize_t (*write) (ASSUAN_CONTEXT, const void *, size_t);
  /* Send a file descriptor.  */
  AssuanError (*sendfd) (ASSUAN_CONTEXT, int);
  /* Receive a file descriptor.  */
  AssuanError (*receivefd) (ASSUAN_CONTEXT, int *);
};  

struct assuan_context_s
{
  AssuanError err_no;
  const char *err_str;
  int os_errno;  /* last system error number used with certain error codes*/

  int confidential;
  int is_server;  /* set if this is context belongs to a server */
  int in_inquire;
  char *hello_line;
  char *okay_line; /* see assan_set_okay_line() */
  
  void *user_pointer;  /* for assuan_[gs]et_pointer () */

  FILE *log_fp;

  struct {
    int fd;
    int eof;
    char line[LINELENGTH];
    int linelen;  /* w/o CR, LF - might not be the same as
                     strlen(line) due to embedded nuls. However a nul
                     is always written at this pos */
    struct {
      char line[LINELENGTH];
      int linelen ;
      int pending; /* i.e. at least one line is available in the attic */
    } attic;
  } inbound;

  struct {
    int fd;
    struct {
      FILE *fp;
      char line[LINELENGTH];
      int linelen; 
      int error;
    } data; 
  } outbound;

  int pipe_mode;  /* We are in pipe mode, i.e. we can handle just one
                     connection and must terminate then */
  pid_t pid;	  /* In pipe mode, the pid of the child server process.  
                     In socket mode, the pid of the server */
  int listen_fd;  /* The fd we are listening on (used by socket servers) */
  int connected_fd; /* helper */

  pid_t client_pid; /* for a socket server the PID of the client or -1
                       if not available */

  /* Used for Unix domain sockets.  */
  struct sockaddr_un myaddr;
  struct sockaddr_un serveraddr;
  /* When reading from datagram sockets, we must read an entire
     message at a time.  This means that we have to do our own
     buffering to be able to get the semantics of read.  */
  void *domainbuffer;
  /* Offset of start of buffer.  */
  int domainbufferoffset;
  /* Bytes buffered.  */
  int domainbuffersize;
  /* Memory allocated.  */
  int domainbufferallocated;

  int *pendingfds;
  int pendingfdscount;

  void (*deinit_handler)(ASSUAN_CONTEXT);  
  int (*accept_handler)(ASSUAN_CONTEXT);
  int (*finish_handler)(ASSUAN_CONTEXT);

  struct cmdtbl_s *cmdtbl;
  size_t cmdtbl_used; /* used entries */
  size_t cmdtbl_size; /* allocated size of table */

  void (*bye_notify_fnc)(ASSUAN_CONTEXT);
  void (*reset_notify_fnc)(ASSUAN_CONTEXT);
  void (*cancel_notify_fnc)(ASSUAN_CONTEXT);
  int  (*option_handler_fnc)(ASSUAN_CONTEXT,const char*, const char*);
  void (*input_notify_fnc)(ASSUAN_CONTEXT, const char *);
  void (*output_notify_fnc)(ASSUAN_CONTEXT, const char *);

  int input_fd;   /* set by INPUT command */
  int output_fd;  /* set by OUTPUT command */

  /* io routines.  */
  struct assuan_io *io;
};

/*-- assuan-pipe-server.c --*/
int _assuan_new_context (ASSUAN_CONTEXT *r_ctx);
void _assuan_release_context (ASSUAN_CONTEXT ctx);

/*-- assuan-domain-connect.c --*/
/* Make a connection to the Unix domain socket NAME and return a new
   Assuan context in CTX.  SERVER_PID is currently not used but may
   become handy in the future.  */
AssuanError _assuan_domain_init (ASSUAN_CONTEXT *r_ctx,
				 int rendezvousfd,
				 pid_t peer);

/*-- assuan-handler.c --*/
int _assuan_register_std_commands (ASSUAN_CONTEXT ctx);

/*-- assuan-buffer.c --*/
int _assuan_read_line (ASSUAN_CONTEXT ctx);
int _assuan_cookie_write_data (void *cookie, const char *buffer, size_t size);
int _assuan_cookie_write_flush (void *cookie);

/*-- assuan-client.c --*/
AssuanError _assuan_read_from_server (ASSUAN_CONTEXT ctx, int *okay, int *off);


/*-- assuan-util.c --*/
void *_assuan_malloc (size_t n);
void *_assuan_calloc (size_t n, size_t m);
void *_assuan_realloc (void *p, size_t n);
void  _assuan_free (void *p);

#define xtrymalloc(a)    _assuan_malloc ((a))
#define xtrycalloc(a,b)  _assuan_calloc ((a),(b))
#define xtryrealloc(a,b) _assuan_realloc((a),(b))
#define xfree(a)         _assuan_free ((a))

#define set_error(c,e,t) assuan_set_error ((c), ASSUAN_ ## e, (t))

void _assuan_log_print_buffer (FILE *fp, const void *buffer, size_t  length);
void _assuan_log_sanitized_string (const char *string);

/*-- assuan-io.c --*/
ssize_t _assuan_simple_read (ASSUAN_CONTEXT ctx, void *buffer, size_t size);
ssize_t _assuan_simple_write (ASSUAN_CONTEXT ctx, const void *buffer,
			      size_t size);

#ifdef HAVE_FOPENCOOKIE
/* We have to implement funopen in terms of glibc's fopencookie. */
FILE *funopen(const void *cookie, cookie_read_function_t *readfn,
              cookie_write_function_t *writefn,
              cookie_seek_function_t *seekfn,
              cookie_close_function_t *closefn);
#endif /*HAVE_FOPENCOOKIE*/

#endif /*ASSUAN_DEFS_H*/

