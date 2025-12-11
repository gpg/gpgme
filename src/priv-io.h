/* priv-io.h - Interface to the private I/O functions.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004, 2005 g10 Code GmbH

   This file is part of GPGME.

   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifndef IO_H
#define IO_H

#ifdef HAVE_W32_SYSTEM
# include <winsock2.h>
# include <windows.h>
#else
# include <sys/socket.h>
#endif

/* For pid_t.  */
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif


/* A single file descriptor passed to spawn.  For child fds, dup_to
   specifies the fd it should become in the child, but only 0, 1 and 2
   are valid values (due to a limitation in the W32 code).  As return
   value, the PEER_NAME fields specify the name of the file
   descriptor in the spawned process, or -1 if no change.  If ARG_LOC
   is not 0, it specifies the index in the argument vector of the
   program which contains a numerical representation of the file
   descriptor for translation purposes.  */
struct spawn_fd_item_s
{
  int fd;
  int dup_to;
  int peer_name;
  int arg_loc;
};

struct io_select_fd_s
{
  int fd;
  int for_read;
  int for_write;
  int signaled;
  void *opaque;
};

/* These function are either defined in posix-io.c or w32-io.c.  */
void _gpgme_io_subsystem_init (void);
int _gpgme_io_socket (int namespace, int style, int protocol);
int _gpgme_io_connect (int fd, struct sockaddr *addr, int addrlen);
int _gpgme_io_read (int fd, void *buffer, size_t count);
int _gpgme_io_write (int fd, const void *buffer, size_t count);
int _gpgme_io_pipe (int filedes[2], int inherit_idx);
int _gpgme_io_close (int fd);
typedef void (*_gpgme_close_notify_handler_t) (int,void*);
int _gpgme_io_set_close_notify (int fd, _gpgme_close_notify_handler_t handler,
				void *value);
int _gpgme_io_set_nonblocking (int fd);

/* Under Windows do not allocate a console.  */
#define IOSPAWN_FLAG_DETACHED 1
/* A flag to tell the spawn function to allow the child process to set
   the foreground window. */
#define IOSPAWN_FLAG_ALLOW_SET_FG 2
/* Don't close any child FDs.  */
#define IOSPAWN_FLAG_NOCLOSE 4
/* Set show window to true for windows */
#define IOSPAWN_FLAG_SHOW_WINDOW 8

/* Spawn the executable PATH with ARGV as arguments.  After forking
   close all fds except for those in FD_LIST in the child, then
   optionally dup() the child fds.  Finally, all fds in the list are
   closed in the parent.  */
int _gpgme_io_spawn (const char *path, char *const argv[], unsigned int flags,
		     struct spawn_fd_item_s *fd_list,
		     void (*atfork) (void *opaque, int reserved),
		     void *atforkvalue, assuan_pid_t *r_pid);

int _gpgme_io_select (struct io_select_fd_s *fds, size_t nfds, int nonblock);

/* Write the printable version of FD to the buffer BUF of length
   BUFLEN.  The printable version is the representation on the command
   line that the child process expects.  */
int _gpgme_io_fd2str (char *buf, int buflen, int fd);

/* Duplicate a file descriptor.  This is more restrictive than dup():
   it assumes that the resulting file descriptors are essentially
   co-equal (for example, no private offset), which is true for pipes
   and sockets (but not files) under Unix with the standard dup()
   function.  Basically, this function is used to reference count the
   status output file descriptor shared between GPGME and libassuan
   (in engine-gpgsm.c).  */
int _gpgme_io_dup (int fd);

#ifndef HAVE_W32_SYSTEM
int _gpgme_io_recvmsg (int fd, struct msghdr *msg, int flags);
int _gpgme_io_sendmsg (int fd, const struct msghdr *msg, int flags);
int _gpgme_io_waitpid (int pid, int hang, int *r_status, int *r_signal);
#endif

#endif /* IO_H */
