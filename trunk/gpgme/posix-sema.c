/* posix-sema.c 
   Copyright (C) 2001 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002 g10 Code GmbH

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
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>

#include "util.h"
#include "sema.h"
#include "ath.h"

void
_gpgme_sema_subsystem_init ()
{
  /* FIXME: we should check that there is only one thread running */
  _gpgme_ath_init ();
}

void
_gpgme_sema_cs_enter (struct critsect_s *s)
{
  _gpgme_ath_mutex_lock (&s->private);
}

void
_gpgme_sema_cs_leave (struct critsect_s *s)
{
  _gpgme_ath_mutex_unlock (&s->private);
}

void
_gpgme_sema_cs_destroy (struct critsect_s *s)
{
  _gpgme_ath_mutex_destroy (&s->private);
  s->private = NULL;
}
