/* posix-sema.c 
 *	Copyright (C) 2001 Werner Koch (dd9jn)
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


#include <config.h>
#ifndef HAVE_DOSISH_SYSTEM

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#include "syshdr.h"

#include "util.h"
#include "sema.h"



void
_gpgme_sema_subsystem_init ()
{
#warning Posix semaphore support has not yet been implemented 
}


void
_gpgme_sema_cs_enter ( struct critsect_s *s )
{
}

void
_gpgme_sema_cs_leave (struct critsect_s *s)
{
}

void
_gpgme_sema_cs_destroy ( struct critsect_s *s )
{
}



#endif /*!HAVE_DOSISH_SYSTEM*/





