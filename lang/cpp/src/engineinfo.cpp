/*
  engineinfo.h
  Copyright (C) 2004 Klarälvdalens Datakonsult AB

  This file is part of GPGME++.

  GPGME++ is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General Public
  License as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  GPGME++ is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Library General Public License for more details.

  You should have received a copy of the GNU Library General Public License
  along with GPGME++; see the file COPYING.LIB.  If not, write to the
  Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  Boston, MA 02110-1301, USA.
*/

#include <config-gpgme++.h>

#include "engineinfo.h"

#include <gpgme.h>

class GpgME::EngineInfo::Private
{
public:
    Private(gpgme_engine_info_t engine = 0) : info(engine) {}
    ~Private()
    {
        info = 0;
    }

    gpgme_engine_info_t info;
};

GpgME::EngineInfo::EngineInfo() : d() {}

GpgME::EngineInfo::EngineInfo(gpgme_engine_info_t engine)
    : d(new Private(engine))
{

}

bool GpgME::EngineInfo::isNull() const
{
    return !d || !d->info;
}

GpgME::Protocol GpgME::EngineInfo::protocol() const
{
    if (isNull()) {
        return UnknownProtocol;
    }
    switch (d->info->protocol) {
    case GPGME_PROTOCOL_OpenPGP: return OpenPGP;
    case GPGME_PROTOCOL_CMS:     return CMS;
    default:
        return UnknownProtocol;
    }
}

const char *GpgME::EngineInfo::fileName() const
{
    return isNull() ? 0 : d->info->file_name;
}

const char *GpgME::EngineInfo::version() const
{
    return isNull() ? 0 : d->info->version;
}

const char *GpgME::EngineInfo::requiredVersion() const
{
    return isNull() ? 0 : d->info->req_version;
}

const char *GpgME::EngineInfo::homeDirectory() const
{
#ifdef HAVE_GPGME_ENGINE_INFO_T_HOME_DIR
    return isNull() ? 0 : d->info->home_dir;
#else
    return 0;
#endif
}
