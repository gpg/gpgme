/* acconfig.h - used by autoheader to make config.h.in
 *	Copyright (C) 2000  Werner Koch (dd9jn)
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
#ifndef GPGME_CONFIG_H
#define GPGME_CONFIG_H

/* need this, because some autoconf tests rely on this (e.g. stpcpy)
 * and it should be used for new programs
 */
#define _GNU_SOURCE  1

@TOP@



#undef HAVE_DRIVE_LETTERS
/* defined if we run on some of the PCDOS like systems (DOS, Windoze. OS/2)
 * with special properties like no file modes */
#undef HAVE_DOSISH_SYSTEM
/* because the Unix gettext has to much overhead on MingW32 systems
 * and these systems lack Posix functions, we use a simplified version
 * of gettext */
#undef USE_SIMPLE_GETTEXT
/* Some systems have mkdir that takes a single argument. */
#undef MKDIR_TAKES_ONE_ARG


@BOTTOM@

/* not yet needed #include "gpgme-defs.h"*/

#endif /*GPGME_CONFIG_H*/
