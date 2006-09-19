/* assuan-defs.c - Internal definitions to Assuan
 *	Copyright (C) 2001, 2002, 2004, 2005 Free Software Foundation, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 */

#ifndef ASSUAN_DEFS_H
#define ASSUAN_DEFS_H

#include <sys/types.h>
#ifndef HAVE_W32_SYSTEM
#include <sys/socket.h>
#include <sys/un.h>
#else
#include <windows.h>
#endif
#include <unistd.h>

#include "assuan.h"

#ifndef HAVE_W32_SYSTEM
#define DIRSEP_C '/'
#else
#define DIRSEP_C '\\'
#endif

#ifdef HAVE_W32_SYSTEM
#define AF_LOCAL AF_UNIX
/* We need to prefix the structure with a sockaddr_in header so we can
   use it later for sendto and recvfrom. */
struct sockaddr_un
{
  short          sun_family;
  unsigned short sun_port;
  struct         in_addr sun_addr;
  char           sun_path[108-2-4]; /* Path name.  */
};

/* Not needed anymore because the current mingw32 defines this in
   sys/types.h */
/* typedef int ssize_t; */

/* Missing W32 functions */
int putc_unlocked (int c, FILE *stream);
void * memrchr (const void *block, int c, size_t size);
char * stpcpy (char *dest, const char *src);
#endif

#define LINELENGTH ASSUAN_LINELENGTH


struct cmdtbl_s
{
  const char *name;
  int (*handler)(assuan_context_t, char *line);
};


/* A structure to dispatch I/O functions.  All these functions need to
   return 0 on success and set ERRNO on failure.  */
struct assuan_io
{
  /* Routine to read from input_fd.  */
  ssize_t (*readfnc) (assuan_context_t, void *, size_t);
  /* Routine to write to output_fd.  */
  ssize_t (*writefnc) (assuan_context_t, const void *, size_t);
  /* Send a file descriptor.  */
  assuan_error_t (*sendfd) (assuan_context_t, int);
  /* Receive a file descriptor.  */
  assuan_error_t (*receivefd) (assuan_context_t, int *);
};


/* The context we use with most functions. */
struct assuan_context_s
{
  assuan_error_t err_no;
  const char *err_str;
  int os_errno;       /* Last system error number used with certain
                         error codes. */

  /* Context specific flags (cf. assuan_flag_t). */
  struct
  {
    unsigned int no_waitpid:1; /* See ASSUAN_NO_WAITPID. */
  } flags;

  int confidential;
  int is_server;      /* Set if this is context belongs to a server */
  int in_inquire;
  char *hello_line;
  char *okay_line;    /* See assuan_set_okay_line() */

  void *user_pointer;  /* For assuan_get_pointer and assuan_set_pointer (). */

  FILE *log_fp;

  struct {
    int fd;
    int eof;
    char line[LINELENGTH];
    int linelen;  /* w/o CR, LF - might not be the same as
                     strlen(line) due to embedded nuls. However a nul
                     is always written at this pos. */
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
                     connection and must terminate then. */
  pid_t pid;	  /* The pid of the peer. */
  int listen_fd;  /* The fd we are listening on (used by socket servers) */
  int connected_fd; /* helper */

  struct {
    int   valid;   /* Whether this structure has valid information. */
    pid_t pid;     /* The pid of the peer. */
    uid_t uid;     /* The uid of the peer. */
    gid_t gid;     /* The gid of the peer. */
  } peercred;

  /* Used for Unix domain sockets.  */
  struct sockaddr_un myaddr;
  struct sockaddr_un serveraddr;

  /* Structure used for unix domain socket buffering.  FIXME: We don't
     use datagrams anymore thus we could get away with a simpler
     buffering approach. */
  struct {
    void *buffer;         /* Malloced buffer. */
    int bufferallocated;  /* Memory allocated.  */
    int bufferoffset;     /* Offset of start of buffer.  */
    int buffersize;       /* Bytes buffered.  */
    
    int pendingfds[5];    /* Array to save received descriptors.  */
    int pendingfdscount;  /* Number of received descriptors. */
  } uds;

  void (*deinit_handler)(assuan_context_t);
  int (*accept_handler)(assuan_context_t);
  int (*finish_handler)(assuan_context_t);

  struct cmdtbl_s *cmdtbl;
  size_t cmdtbl_used; /* used entries */
  size_t cmdtbl_size; /* allocated size of table */

  void (*bye_notify_fnc)(assuan_context_t);
  void (*reset_notify_fnc)(assuan_context_t);
  void (*cancel_notify_fnc)(assuan_context_t);
  int  (*option_handler_fnc)(assuan_context_t,const char*, const char*);
  void (*input_notify_fnc)(assuan_context_t, const char *);
  void (*output_notify_fnc)(assuan_context_t, const char *);

  int input_fd;   /* set by INPUT command */
  int output_fd;  /* set by OUTPUT command */

  /* io routines.  */
  struct assuan_io *io;
};

/*-- assuan-pipe-server.c --*/
int _assuan_new_context (assuan_context_t *r_ctx);
void _assuan_release_context (assuan_context_t ctx);

/*-- assuan-uds.c --*/
void _assuan_uds_close_fds (assuan_context_t ctx);
void _assuan_uds_deinit (assuan_context_t ctx);
void _assuan_init_uds_io (assuan_context_t ctx);


/*-- assuan-handler.c --*/
int _assuan_register_std_commands (assuan_context_t ctx);

/*-- assuan-buffer.c --*/
assuan_error_t _assuan_read_line (assuan_context_t ctx);
int _assuan_cookie_write_data (void *cookie, const char *buffer, size_t size);
int _assuan_cookie_write_flush (void *cookie);
assuan_error_t _assuan_write_line (assuan_context_t ctx, const char *prefix,
                                   const char *line, size_t len);

/*-- assuan-client.c --*/
assuan_error_t _assuan_read_from_server (assuan_context_t ctx,
                                         int *okay, int *off);

/*-- assuan-error.c --*/


/* Map error codes as used in this implementaion to the libgpg-error
   codes. */
assuan_error_t _assuan_error (int oldcode);

/* Extrac the erro code from A.  This works for both the old and the
   new style error codes. This needs to be whenever an error code is
   compared. */
#define err_code(a) ((a) & 0x00ffffff)

/* Check whether A is the erro code for EOF.  We allow forold and new
   style EOF error codes here.  */
#define err_is_eof(a) ((a) == (-1) || err_code (a) == 16383)



/*-- assuan-util.c --*/
void *_assuan_malloc (size_t n);
void *_assuan_calloc (size_t n, size_t m);
void *_assuan_realloc (void *p, size_t n);
void  _assuan_free (void *p);

#define xtrymalloc(a)    _assuan_malloc ((a))
#define xtrycalloc(a,b)  _assuan_calloc ((a),(b))
#define xtryrealloc(a,b) _assuan_realloc((a),(b))
#define xfree(a)         _assuan_free ((a))

#define set_error(c,e,t) \
        assuan_set_error ((c), _assuan_error (ASSUAN_ ## e), (t))

#ifdef HAVE_W32_SYSTEM
const char *_assuan_w32_strerror (int ec);
#define w32_strerror(e) _assuan_w32_strerror ((e))
#endif /*HAVE_W32_SYSTEM*/


/*-- assuan-logging.c --*/
void _assuan_set_default_log_stream (FILE *fp);

void _assuan_log_printf (const char *format, ...)
#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
 __attribute__ ((format (printf,1,2)))
#endif
     ;
void _assuan_log_print_buffer (FILE *fp, const void *buffer, size_t  length);
void _assuan_log_sanitized_string (const char *string);


/*-- assuan-io.c --*/
pid_t _assuan_waitpid (pid_t pid, int *status, int options);

ssize_t _assuan_simple_read (assuan_context_t ctx, void *buffer, size_t size);
ssize_t _assuan_simple_write (assuan_context_t ctx, const void *buffer,
			      size_t size);
ssize_t _assuan_simple_sendmsg (assuan_context_t ctx, struct msghdr *msg);
ssize_t _assuan_simple_recvmsg (assuan_context_t ctx, struct msghdr *msg);

/*-- assuan-socket.c --*/
int _assuan_close (int fd);
int _assuan_sock_new (int domain, int type, int proto);
int _assuan_sock_bind (int sockfd, struct sockaddr *addr, int addrlen);
int _assuan_sock_connect (int sockfd, struct sockaddr *addr, int addrlen);

#ifdef HAVE_FOPENCOOKIE
/* We have to implement funopen in terms of glibc's fopencookie. */
FILE *_assuan_funopen(void *cookie,
                      cookie_read_function_t *readfn,
                      cookie_write_function_t *writefn,
                      cookie_seek_function_t *seekfn,
                      cookie_close_function_t *closefn);
#define funopen(a,r,w,s,c) _assuan_funopen ((a), (r), (w), (s), (c))
#endif /*HAVE_FOPENCOOKIE*/

/* Prototypes for replacement functions.  */
#ifndef HAVE_MEMRCHR
void *memrchr (const void *block, int c, size_t size);
#endif
#ifndef HAVE_STPCPY
char *stpcpy (char *dest, const char *src);
#endif
#ifndef HAVE_SETENV
#define setenv _assuan_setenv
#define unsetenv _assuan_unsetenv
#define clearenv _assuan_clearenv
int setenv (const char *name, const char *value, int replace);
#endif
#ifndef HAVE_PUTC_UNLOCKED
int putc_unlocked (int c, FILE *stream)
#endif

#define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
#define DIMof(type,member)   DIM(((type *)0)->member)


#endif /*ASSUAN_DEFS_H*/
