/* sema.h - Definitions for semaphores.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2003, 2004, 2007 g10 Code GmbH

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

#ifndef SEMA_H
#define SEMA_H

#include <gpg-error.h>

#define DEFINE_GLOBAL_LOCK(name) \
  gpgrt_lock_t name  = GPGRT_LOCK_INITIALIZER

#define DEFINE_STATIC_LOCK(name) \
  static gpgrt_lock_t name = GPGRT_LOCK_INITIALIZER

#define INIT_LOCK(name) \
  name = (gpgrt_lock_t) GPGRT_LOCK_INITIALIZER

#define DECLARE_LOCK(name) gpgrt_lock_t name

#define DESTROY_LOCK(name) gpgrt_lock_destroy(&name)

#define LOCK(name) gpgrt_lock_lock(&name)

#define UNLOCK(name) gpgrt_lock_unlock(&name)

#endif /* SEMA_H */
