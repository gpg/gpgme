/* engine.c 
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "gpgme.h"
#include "util.h"

#include "engine.h"
#include "rungpg.h"
#include "engine-gpgsm.h"

struct engine_object_s
  {
    GpgmeProtocol protocol;

    const char *path;
    const char *version;

    union
      {
        GpgObject gpg;
        GpgsmObject gpgsm;
      } engine;
};

/* Get the path of the engine for PROTOCOL.  */
const char *
_gpgme_engine_get_path (GpgmeProtocol proto)
{
  switch (proto)
    {
    case GPGME_PROTOCOL_OpenPGP:
      return _gpgme_get_gpg_path ();
    case GPGME_PROTOCOL_CMS:
      return _gpgme_get_gpgsm_path ();
    default:
      return NULL;
    }
}

/* Get the version number of the engine for PROTOCOL.  */
const char *
_gpgme_engine_get_version (GpgmeProtocol proto)
{
  switch (proto)
    {
    case GPGME_PROTOCOL_OpenPGP:
      return _gpgme_gpg_get_version ();
    case GPGME_PROTOCOL_CMS:
      return _gpgme_gpgsm_get_version ();
    default:
      return NULL;
    }
}

GpgmeError
gpgme_engine_check_version (GpgmeProtocol proto)
{
  switch (proto)
    {
    case GPGME_PROTOCOL_OpenPGP:
      return _gpgme_gpg_check_version ();
    case GPGME_PROTOCOL_CMS:
      return _gpgme_gpgsm_check_version ();
    default:
      return mk_error (Invalid_Value);
    }
}

GpgmeError
_gpgme_engine_new (GpgmeProtocol proto, EngineObject *r_engine)
{
  EngineObject engine;
  GpgmeError err = 0;

  engine = xtrycalloc (1, sizeof *engine);
  if (!engine)
    {
      err = mk_error (Out_Of_Core);
      goto leave;
    }

  engine->protocol = proto;
  switch (proto)
    {
    case GPGME_PROTOCOL_OpenPGP:
      err =_gpgme_gpg_new (&engine->engine.gpg);
      break;
    case GPGME_PROTOCOL_CMS:
      err = _gpgme_gpgsm_new (&engine->engine.gpgsm);
      if (err)
	goto leave;
      break;
    default:
      err = mk_error (Invalid_Value);
    }
  if (err)
    goto leave;

  engine->path = _gpgme_engine_get_path (proto);
  engine->version = _gpgme_engine_get_version (proto);

  if (!engine->path || !engine->version)
    {
      err = mk_error (Invalid_Engine);
      goto leave;
    }

 leave:
  if (err)
    _gpgme_engine_release (engine);
  else
    *r_engine = engine;
  
  return err;
}

void
_gpgme_engine_release (EngineObject engine)
{
  if (!engine)
    return;

  switch (engine->protocol)
    {
    case GPGME_PROTOCOL_OpenPGP:
      _gpgme_gpg_release (engine->engine.gpg);
      break;
    case GPGME_PROTOCOL_CMS:
      _gpgme_gpgsm_release (engine->engine.gpgsm);
      break;
    default:
      break;
    }
  xfree (engine);
}
