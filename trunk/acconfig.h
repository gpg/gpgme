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
 * and it should be used for new programs  */
#define _GNU_SOURCE  1
/* To allow the use of gpgme in multithreaded programs we have to use 
 * special features from the library.  
 * IMPORTANT: gpgme is not yet fully reentrant and you should use it
 * only from one thread. */
#define _REENTRANT 1 

@TOP@

/* defined if we run on some of the PCDOS like systems (DOS, Windoze. OS/2)
 * with special properties like no file modes */
#undef HAVE_DOSISH_SYSTEM
/* defined if the filesystem uses driver letters */
#undef HAVE_DRIVE_LETTERS
/* Some systems have a mkdir that takes a single argument. */
#undef MKDIR_TAKES_ONE_ARG

/* Path to the GnuPG binary.  */
#undef GPG_PATH
/* Min. needed GnuPG version. */
#undef NEED_GPG_VERSION

/* Path to the GpgSM binary.  */
#undef GPGSM_PATH
/* Min. needed GpgSM version. */
#undef NEED_GPGSM_VERSION

/* Stuff needed by jnlib.  */
#undef HAVE_BYTE_TYPEDEF
#undef HAVE_USHORT_TYPEDEF
#undef HAVE_ULONG_TYPEDEF
#undef HAVE_U16_TYPEDEF
#undef HAVE_U32_TYPEDEF



@BOTTOM@

/* not yet needed #include "gpgme-defs.h"*/

#endif /*GPGME_CONFIG_H*/
