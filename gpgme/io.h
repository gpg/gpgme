/* io.h - Interface to the I/O functions.
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

#ifndef IO_H
#define IO_H

/* A single file descriptor passed to spawn.  For child fds, dup_to
   specifies the fd it should become in the child.  */
struct spawn_fd_item_s
{
  int fd;
  int dup_to;
};

struct io_select_fd_s
{
  int fd;
  int for_read;
  int for_write;
  int signaled;
  int frozen;
  void *opaque;
};

/* These function are either defined in posix-io.c or w32-io.c.  */
void _gpgme_io_subsystem_init (void);
int _gpgme_io_read (int fd, void *buffer, size_t count);
int _gpgme_io_write (int fd, const void *buffer, size_t count);
int _gpgme_io_pipe (int filedes[2], int inherit_idx);
int _gpgme_io_close (int fd);
int _gpgme_io_set_close_notify (int fd, void (*handler) (int, void *),
				void *value);
int _gpgme_io_set_nonblocking (int fd);

/* Spawn the executable PATH with ARGV as arguments, after forking
   close all fds in FD_PARENT_LIST in the parent and close or dup all
   fds in FD_CHILD_LIST in the child.  */
int _gpgme_io_spawn (const char *path, char **argv,
		     struct spawn_fd_item_s *fd_child_list,
		     struct spawn_fd_item_s *fd_parent_list);
int _gpgme_io_waitpid (int pid, int hang, int *r_status, int *r_signal);
int _gpgme_io_kill (int pid, int hard);
int _gpgme_io_select (struct io_select_fd_s *fds, size_t nfds, int nonblock);

#endif /* IO_H */



