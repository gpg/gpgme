/* w32-sema.c
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
#include <fcntl.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#include <io.h>

#include "util.h"
#include "sema.h"
#include "debug.h"

static void
sema_fatal (const char *text)
{
    fprintf (stderr, "sema.c: %s\n", text);
    abort ();
}


static void
critsect_init (struct critsect_s *s)
{
    CRITICAL_SECTION *mp;
    static CRITICAL_SECTION init_lock;
    static int initialized;

    if (!initialized) {
        /* The very first time we call this function, we assume that
	   only one thread is running, so that we can bootstrap the
	   semaphore code.  */
        InitializeCriticalSection (&init_lock);
        initialized = 1;
    }
    if (!s)
        return; /* we just want to initialize ourself */

    /* first test whether it is really not initialized */
    EnterCriticalSection (&init_lock);
    if ( s->priv ) {
        LeaveCriticalSection (&init_lock);
        return;
    }
    /* now init it */
    mp = malloc ( sizeof *mp );
    if (!mp) {
        LeaveCriticalSection (&init_lock);
        sema_fatal ("out of core while creating critical section lock");
    }
    InitializeCriticalSection (mp);
    s->priv = mp;
    LeaveCriticalSection (&init_lock);
}

void
_gpgme_sema_subsystem_init ()
{
    /* fixme: we should check that there is only one thread running */
    critsect_init (NULL);
}


void
_gpgme_sema_cs_enter ( struct critsect_s *s )
{
    if (!s->priv)
        critsect_init (s);
    EnterCriticalSection ( (CRITICAL_SECTION*)s->priv );
}

void
_gpgme_sema_cs_leave (struct critsect_s *s)
{
    if (!s->priv)
        critsect_init (s);
    LeaveCriticalSection ((CRITICAL_SECTION*)s->priv);
}

void
_gpgme_sema_cs_destroy ( struct critsect_s *s )
{
    if (s && s->priv) {
        DeleteCriticalSection ((CRITICAL_SECTION*)s->priv);
        free (s->priv);
        s->priv = NULL;
    }
}
