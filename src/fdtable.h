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

/* Remove FD from the table.  This also runs the close handlers.  */
gpg_error_t _gpgme_fdtable_remove (int fd);


#endif /*GPGME_FDTABLE_H*/
