/*
  engineinfo.h
  Copyright (C) 2004 Klarälvdalens Datakonsult AB
  2016 Bundesamt für Sicherheit in der Informationstechnik
  Software engineering by Intevation GmbH

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

#include "engineinfo.h"

#include <gpgme.h>

class GpgME::EngineInfo::Private
{
public:
    Private(gpgme_engine_info_t engine = nullptr) : info(engine) {}
    ~Private()
    {
        info = nullptr;
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
    return isNull() ? nullptr : d->info->file_name;
}

const char *GpgME::EngineInfo::version() const
{
    return isNull() ? nullptr : d->info->version;
}

GpgME::EngineInfo::Version GpgME::EngineInfo::engineVersion() const
{
    return Version(version());
}

const char *GpgME::EngineInfo::requiredVersion() const
{
    return isNull() ? nullptr : d->info->req_version;
}

const char *GpgME::EngineInfo::homeDirectory() const
{
    return isNull() ? nullptr : d->info->home_dir;
}
