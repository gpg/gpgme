/* engine-gpgsm.c -  GpgSM engine
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *      Copyright (C) 2001 g10 Code GmbH
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "gpgme.h"
#include "util.h"
#include "types.h"
#include "ops.h"

#include "engine-gpgsm.h"

/* FIXME: Correct check?  */
#ifdef GPGSM_PATH
#define ENABLE_GPGSM 1
#endif

#ifdef ENABLE_GPGSM

#include "assuan.h"

struct gpgsm_object_s
{
  ASSUAN_CONTEXT assuan_ctx;
};

const char *
_gpgme_gpgsm_get_version (void)
{
  static const char *gpgsm_version;

  /* FIXME: Locking.  */
  if (!gpgsm_version)
    gpgsm_version = _gpgme_get_program_version (_gpgme_get_gpgsm_path ());

  return gpgsm_version;
}

GpgmeError
_gpgme_gpgsm_check_version (void)
{
  return _gpgme_compare_versions (_gpgme_gpgsm_get_version (),
				  NEED_GPGSM_VERSION)
    ? 0 : mk_error (Invalid_Engine);
}

GpgmeError
_gpgme_gpgsm_new (GpgsmObject *r_gpgsm)
{
  GpgmeError err = 0;
  GpgsmObject gpgsm;
  char *argv[] = { "gpgsm", "--server", NULL };

  *r_gpgsm = NULL;
  gpgsm = xtrycalloc (1, sizeof *gpgsm);
  if (!gpgsm)
    {
      err = mk_error (Out_Of_Core);
      goto leave;
    }

  err = assuan_pipe_connect (&gpgsm->assuan_ctx,
			     _gpgme_get_gpgsm_path (), argv);

 leave:
  if (err)
    _gpgme_gpgsm_release (gpgsm);
  else
    *r_gpgsm = gpgsm;

  return err;
}

void
_gpgme_gpgsm_release (GpgsmObject gpgsm)
{
  if (!gpgsm)
    return;

  assuan_pipe_disconnect (gpgsm->assuan_ctx);
  xfree (gpgsm);
}

#else	/* ENABLE_GPGSM */

const char *
_gpgme_gpgsm_get_version (void)
{
  return NULL;
}

GpgmeError
_gpgme_gpgsm_check_version (void)
{
  return mk_error (Invalid_Engine);
}

GpgmeError
_gpgme_gpgsm_new (GpgsmObject *r_gpgsm)
{
  return mk_error (Invalid_Engine);
}

void
_gpgme_gpgsm_release (GpgsmObject gpgsm)
{
  return;
}

#endif	/* ! ENABLE_GPGSM */
