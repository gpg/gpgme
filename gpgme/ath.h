/* ath.h - interfaces for self-adapting thread-safeness library
 *      Copyright (C) 2002 g10 Code GmbH
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

#ifndef ATH_H
#define ATH_H

#include <sys/types.h>

/* Define ATH_EXT_SYM_PREFIX if you want to give all external symbols
   a prefix.  */
/* #define ATH_EXT_SYM_PREFIX _gpgme_ */

#ifdef ATH_EXT_SYM_PREFIX
#define ath_pkg_init MUTEX_EXT_SYM_PREFIX##ath_pkg_init
#define ath_mutex_init MUTEX_EXT_SYM_PREFIX##ath_mutex_init
#define ath_mutex_destroy MUTEX_EXT_SYM_PREFIX##ath_mutex_destroy
#define ath_mutex_lock MUTEX_EXT_SYM_PREFIX##ath_mutex_lock
#define ath_mutex_pthread_available \
  MUTEX_EXT_SYM_PREFIX##ath_mutex_pthread_available
#define ath_mutex_pth_available \
  MUTEX_EXT_SYM_PREFIX##ath_mutex_pth_available
#define ath_mutex_dummy_available \
  MUTEX_EXT_SYM_PREFIX##ath_mutex_dummy_available
#define ath_read MUTEX_EXT_SYM##ath_read
#define ath_write MUTEX_EXT_SYM##ath_write
#define ath_select MUTEX_EXT_SYM##ath_select
#define ath_waitpid MUTEX_EXT_SYM##ath_waitpid
#define ath_mutex_pthread_available \
  MUTEX_EXT_SYM_PREFIX##ath_mutex_pthread_available
#define ath_mutex_pthr_available \
  MUTEX_EXT_SYM_PREFIX##ath_mutex_pthr_available
#define ath_mutex_dummy_available \
  MUTEX_EXT_SYM_PREFIX##ath_mutex_dummy_available
#endif


typedef void *ath_mutex_t;
#define ATH_MUTEX_INITIALIZER 0;

/* Functions for mutual exclusion.  */
int ath_mutex_init (ath_mutex_t *mutex);
int ath_mutex_destroy (ath_mutex_t *mutex);
int ath_mutex_lock (ath_mutex_t *mutex);
int ath_mutex_unlock (ath_mutex_t *mutex);

/* Replacement for the POSIX functions, which can be used to allow
   other (user-level) threads to run.  */
ssize_t ath_read (int fd, void *buf, size_t nbytes);
ssize_t ath_write (int fd, const void *buf, size_t nbytes);
ssize_t ath_select (int nfd, fd_set *rset, fd_set *wset, fd_set *eset,
		    struct timeval *timeout);
ssize_t ath_waitpid (pid_t pid, int *status, int options);


struct ath_ops
{
  int (*mutex_init) (void **priv, int just_check);
  int (*mutex_destroy) (void *priv);
  int (*mutex_lock) (void *priv);
  int (*mutex_unlock) (void *priv);
  ssize_t (*read) (int fd, void *buf, size_t nbytes);
  ssize_t (*write) (int fd, const void *buf, size_t nbytes);
  ssize_t (*select) (int nfd, fd_set *rset, fd_set *wset, fd_set *eset,
		     struct timeval *timeout);
  ssize_t (*waitpid) (pid_t pid, int *status, int options);
};

/* Initialize the any-thread package.  */
void ath_init (void);

/* Used by ath_pkg_init.  */
struct ath_ops *ath_pthread_available (void);
struct ath_ops *ath_pth_available (void);
struct ath_ops *ath_dummy_available (void);

#endif	/* ATH_H */
