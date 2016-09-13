#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <stdlib.h>
#include <errno.h>

#include "assuan.h"

#include "gpgme.h"
#include "ath.h"
#include "priv-io.h"
#include "debug.h"


struct assuan_malloc_hooks _gpgme_assuan_malloc_hooks =
  {
    malloc,
    realloc,
    free
  };


int
_gpgme_assuan_log_cb (assuan_context_t ctx, void *hook,
		      unsigned int cat, const char *msg)
{
  (void)ctx;
  (void)hook;
  (void)cat;

  if (msg == NULL)
    return 1;

  _gpgme_debug (DEBUG_ASSUAN, "%s", msg);
  return 0;
}


static void
my_usleep (assuan_context_t ctx, unsigned int usec)
{
  /* FIXME: Add to ath.  */
  __assuan_usleep (ctx, usec);
}


/* Create a pipe with an inheritable end.  */
static int
my_pipe (assuan_context_t ctx, assuan_fd_t fds[2], int inherit_idx)
{
  int res;
  int gfds[2];

  (void)ctx;

  res = _gpgme_io_pipe (gfds, inherit_idx);

  /* For now... */
  fds[0] = (assuan_fd_t) gfds[0];
  fds[1] = (assuan_fd_t) gfds[1];

  return res;
}


/* Close the given file descriptor, created with _assuan_pipe or one
   of the socket functions.  */
static int
my_close (assuan_context_t ctx, assuan_fd_t fd)
{
  (void)ctx;
  return _gpgme_io_close ((int) fd);
}


static gpgme_ssize_t
my_read (assuan_context_t ctx, assuan_fd_t fd, void *buffer, size_t size)
{
  (void)ctx;
  return _gpgme_io_read ((int) fd, buffer, size);
}


static gpgme_ssize_t
my_write (assuan_context_t ctx, assuan_fd_t fd, const void *buffer, size_t size)
{
  (void)ctx;
  return _gpgme_io_write ((int) fd, buffer, size);
}


static int
my_recvmsg (assuan_context_t ctx, assuan_fd_t fd, assuan_msghdr_t msg,
	    int flags)
{
  (void)ctx;
#ifdef HAVE_W32_SYSTEM
  gpg_err_set_errno (ENOSYS);
  return -1;
#else
  return _gpgme_io_recvmsg ((int) fd, msg, flags);
#endif
}



static int
my_sendmsg (assuan_context_t ctx, assuan_fd_t fd, const assuan_msghdr_t msg,
	    int flags)
{
  (void)ctx;
#ifdef HAVE_W32_SYSTEM
  gpg_err_set_errno (ENOSYS);
  return -1;
#else
  return _gpgme_io_sendmsg ((int) fd, msg, flags);
#endif
}


/* If NAME is NULL, don't exec, just fork.  FD_CHILD_LIST is modified
   to reflect the value of the FD in the peer process (on
   Windows).  */
static int
my_spawn (assuan_context_t ctx, pid_t *r_pid, const char *name,
	  const char **argv,
	  assuan_fd_t fd_in, assuan_fd_t fd_out,
	  assuan_fd_t *fd_child_list,
	  void (*atfork) (void *opaque, int reserved),
	  void *atforkvalue, unsigned int flags)
{
  int err;
  struct spawn_fd_item_s *fd_items;
  int i;

  (void)ctx;
  (void)flags;

  assert (name);

  if (! name)
    {
      gpg_err_set_errno (ENOSYS);
      return -1;
    }

  i = 0;
  if (fd_child_list)
    {
      while (fd_child_list[i] != ASSUAN_INVALID_FD)
	i++;
    }
  /* fd_in, fd_out, terminator */
  i += 3;
  fd_items = calloc (i, sizeof (struct spawn_fd_item_s));
  if (! fd_items)
    return -1;
  i = 0;
  if (fd_child_list)
    {
      while (fd_child_list[i] != ASSUAN_INVALID_FD)
	{
	  fd_items[i].fd = (int) fd_child_list[i];
	  fd_items[i].dup_to = -1;
	  i++;
	}
    }
  if (fd_in != ASSUAN_INVALID_FD)
    {
      fd_items[i].fd = (int) fd_in;
      fd_items[i].dup_to = 0;
      i++;
    }
  if (fd_out != ASSUAN_INVALID_FD)
    {
      fd_items[i].fd = (int) fd_out;
      fd_items[i].dup_to = 1;
      i++;
    }
  fd_items[i].fd = -1;
  fd_items[i].dup_to = -1;

  err = _gpgme_io_spawn (name, (char*const*)argv,
                         (IOSPAWN_FLAG_NOCLOSE | IOSPAWN_FLAG_DETACHED),
			 fd_items, atfork, atforkvalue, r_pid);
  if (! err)
    {
      i = 0;

      if (fd_child_list)
	{
	  while (fd_child_list[i] != ASSUAN_INVALID_FD)
	    {
	      fd_child_list[i] = (assuan_fd_t) fd_items[i].peer_name;
	      i++;
	    }
	}
    }
  free (fd_items);
  return err;
}


/* If action is 0, like waitpid.  If action is 1, just release the PID?  */
static pid_t
my_waitpid (assuan_context_t ctx, pid_t pid,
	    int nowait, int *status, int options)
{
  (void)ctx;
#ifdef HAVE_W32_SYSTEM
  CloseHandle ((HANDLE) pid);
#else
  /* We can't just release the PID, a waitpid is mandatory.  But
     NOWAIT in POSIX systems just means the caller already did the
     waitpid for this child.  */
  if (! nowait)
    return _gpgme_ath_waitpid (pid, status, options);
#endif
  return 0;
}




static int
my_socketpair (assuan_context_t ctx, int namespace, int style,
	       int protocol, assuan_fd_t filedes[2])
{
#ifdef HAVE_W32_SYSTEM
  gpg_err_set_errno (ENOSYS);
  return -1;
#else
  /* FIXME: Debug output missing.  */
  return __assuan_socketpair (ctx, namespace, style, protocol, filedes);
#endif
}


static int
my_socket (assuan_context_t ctx, int namespace, int style, int protocol)
{
  (void)ctx;
  return _gpgme_io_socket (namespace, style, protocol);
}


static int
my_connect (assuan_context_t ctx, int sock, struct sockaddr *addr,
	    socklen_t length)
{
  (void)ctx;
  return _gpgme_io_connect (sock, addr, length);
}


/* Note for Windows: Ignore the incompatible pointer type warning for
   my_read and my_write.  Mingw has been changed to use int for
   ssize_t on 32 bit systems while we use long.  For 64 bit we use
   int64_t while mingw uses __int64_t.  It doe not matter at all
   because under Windows long and int are both 32 bit even on 64
   bit.  */
struct assuan_system_hooks _gpgme_assuan_system_hooks =
  {
    ASSUAN_SYSTEM_HOOKS_VERSION,
    my_usleep,
    my_pipe,
    my_close,
    my_read,
    my_write,
    my_recvmsg,
    my_sendmsg,
    my_spawn,
    my_waitpid,
    my_socketpair,
    my_socket,
    my_connect
  };

