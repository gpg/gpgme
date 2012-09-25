/* posix-sema.c
   Copyright (C) 2001 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2004, 2007 g10 Code GmbH

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include "util.h"
#include "sema.h"
#include "ath.h"

void
_gpgme_sema_subsystem_init ()
{
}

void
_gpgme_sema_cs_enter (struct critsect_s *s)
{
  _gpgme_ath_mutex_lock (&s->priv);
}

void
_gpgme_sema_cs_leave (struct critsect_s *s)
{
  _gpgme_ath_mutex_unlock (&s->priv);
}

void
_gpgme_sema_cs_destroy (struct critsect_s *s)
{
  _gpgme_ath_mutex_destroy (&s->priv);
  s->priv = NULL;
}
