/* sys-util.h - System utilities not generally used.
 * Copyright (C) 2013 g10 Code GmbH
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
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SYS_UTIL_H
#define SYS_UTIL_H

/*-- {posix,w32}-util.c --*/
const char *_gpgme_get_gpg_path (void);
const char *_gpgme_get_gpgsm_path (void);
const char *_gpgme_get_gpgconf_path (void);
const char *_gpgme_get_g13_path (void);

#endif /* SYS_UTIL_H */
