/* fdtable.h - Keep track of file descriptors.
 * Copyright (C) 2019 g10 Code GmbH
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef GPGME_FDTABLE_H
#define GPGME_FDTABLE_H

#include "priv-io.h"

/* Flags used by _gpgme_fdtable_get_fds.  */
#define FDTABLE_FLAG_ACTIVE    1  /* Only those with the active flag set.   */
#define FDTABLE_FLAG_DONE      2  /* Only those with the done flag set      */
#define FDTABLE_FLAG_NOT_DONE  4  /* Only those with the done flag cleared. */
#define FDTABLE_FLAG_FOR_READ  16 /* Only those with the signaled flag set. */
#define FDTABLE_FLAG_FOR_WRITE 32 /* Only those with the for_read flag set. */
#define FDTABLE_FLAG_SIGNALED  64 /* Only those with the signaled flag set. */
#define FDTABLE_FLAG_NOT_SIGNALED 128 /* Ditto reversed.                    */
#define FDTABLE_FLAG_CLEAR   256  /* Clear the signaled flag.               */


/* The handler type associated with an FD.  It is called with the FD
 * and the registered pointer.  The handler may return an error code
 * but there is no guarantee that this code is used; in particular
 * errors from close notifications can't inhibit the the closing.  */
typedef gpg_error_t (*fdtable_handler_t) (int, void*);


/* Insert a new FD into the table.  */
gpg_error_t _gpgme_fdtable_insert (int fd);

/* Add a close notification handler to the FD item.  */
gpg_error_t _gpgme_fdtable_add_close_notify (int fd,
                                             fdtable_handler_t handler,
                                             void *value);
/* Set or remove the I/O callback.  */
gpg_error_t _gpgme_fdtable_set_io_cb (int fd, uint64_t owner, int direction,
                                      gpgme_io_cb_t cb, void *cb_value);

/* Set all FDs of OWNER into the active state.  */
gpg_error_t _gpgme_fdtable_set_active (uint64_t owner);

/* Set all FDs of OWNER into the done state.  */
gpg_error_t _gpgme_fdtable_set_done (uint64_t owner,
                                     gpg_error_t status, gpg_error_t op_err);

/* Walk over all FDS and copy the signaled flag if set.  */
void _gpgme_fdtable_set_signaled (io_select_t fds, unsigned int nfds);

/* Remove FD from the table.  This also runs the close handlers.  */
gpg_error_t _gpgme_fdtable_remove (int fd);

/* Return the number of active I/O callbacks for OWNER.  */
unsigned int _gpgme_fdtable_get_count (uint64_t owner, unsigned int flags);

/* Run all the signaled IO callbacks of OWNER.  */
gpg_error_t _gpgme_fdtable_run_io_cbs (uint64_t owner, gpg_error_t *r_op_err,
                                       uint64_t *r_owner);

/* Return a list of FDs matching the OWNER and FLAGS.  */
unsigned int _gpgme_fdtable_get_fds (io_select_t *r_fds,
                                     uint64_t owner, unsigned int flags);

/* Return the status info for the entry of OWNER.  */
uint64_t _gpgme_fdtable_get_done (uint64_t owner, gpg_error_t *r_status,
                                  gpg_error_t *r_op_err);

#endif /*GPGME_FDTABLE_H*/
