/* swdbresult.cpp - wraps gpgme swdb result / query
  Copyright (C) 2016 by Bundesamt für Sicherheit in der Informationstechnik
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

#include "swdbresult.h"

#include <istream>

#include "error.h"

#include "gpgme.h"

class GpgME::SwdbResult::Private
{
public:
    Private() {}
    Private(gpgme_query_swdb_result_t result)
        : mResult(result ? new _gpgme_op_query_swdb_result (*result) : nullptr)
    {
        if (!result) {
            mResult->name = nullptr;
            return;
        }
        if (result->name) {
            mResult->name = strdup(result->name);
        }
        if (result->version) {
            mVersion = result->version;
        }
        if (result->iversion) {
            mIVersion = result->iversion;
        }
    }

    Private(const Private &other)
        : mResult(other.mResult)
    {
        if (mResult && mResult->name) {
            mResult->name = strdup(mResult->name);
        }
        mVersion = other.mVersion;
        mIVersion = other.mIVersion;
    }

    ~Private()
    {
        if (mResult) {
            std::free(mResult->name);
            delete mResult;
        }
    }

    GpgME::EngineInfo::Version mVersion;
    GpgME::EngineInfo::Version mIVersion;
    gpgme_query_swdb_result_t mResult;
};

GpgME::SwdbResult::SwdbResult(gpgme_query_swdb_result_t result)
    : d(new Private(result))
{
}

GpgME::SwdbResult::SwdbResult() : d()
{
}

bool GpgME::SwdbResult::isNull() const
{
    return !d || !d->mResult;
}

std::string GpgME::SwdbResult::name() const
{
    if (isNull() || !d->mResult->name) {
        return std::string();
    }
    return d->mResult->name;
}

GpgME::EngineInfo::Version GpgME::SwdbResult::version() const
{
    if (isNull()) {
        return GpgME::EngineInfo::Version();
    }
    return d->mVersion;
}

GpgME::EngineInfo::Version GpgME::SwdbResult::installedVersion() const
{
    if (isNull()) {
        return GpgME::EngineInfo::Version();
    }
    return d->mIVersion;
}

unsigned long GpgME::SwdbResult::created() const
{
    return isNull() ? 0 : d->mResult->created;
}

unsigned long GpgME::SwdbResult::retrieved() const
{
    return isNull() ? 0 : d->mResult->retrieved;
}

unsigned long GpgME::SwdbResult::releaseDate() const
{
    return isNull() ? 0 : d->mResult->reldate;
}

bool GpgME::SwdbResult::warning() const
{
    return isNull() ? 0 : d->mResult->warning;
}

bool GpgME::SwdbResult::update() const
{
    return isNull() ? 0 : d->mResult->update;
}

bool GpgME::SwdbResult::noinfo() const
{
    return isNull() ? 0 : d->mResult->noinfo;
}

bool GpgME::SwdbResult::unknown() const
{
    return isNull() ? 0 : d->mResult->unknown;
}

bool GpgME::SwdbResult::error() const
{
    return isNull() ? 0 : d->mResult->error;
}

bool GpgME::SwdbResult::tooOld() const
{
    return isNull() ? 0 : d->mResult->tooold;
}

bool GpgME::SwdbResult::urgent() const
{
    return isNull() ? 0 : d->mResult->urgent;
}

std::vector<GpgME::SwdbResult> GpgME::SwdbResult::query(const char *name,
                                                        const char *iversion,
                                                        Error *err)
{
  std::vector <GpgME::SwdbResult> ret;
  gpgme_ctx_t ctx;
  gpgme_error_t gpgerr = gpgme_new(&ctx);

  if (gpgerr) {
      if (err) {
        *err = Error (gpgerr);
      }
      return ret;
  }

  gpgerr = gpgme_set_protocol(ctx, GPGME_PROTOCOL_GPGCONF);

  if (gpgerr) {
      if (err) {
        *err = Error(gpgerr);
      }
      gpgme_release(ctx);
      return ret;
  }

  gpgerr = gpgme_op_query_swdb(ctx, name, iversion, 0);

  if (gpgerr) {
      if (err) {
        *err = Error(gpgerr);
      }
      gpgme_release(ctx);
      return ret;
  }
  gpgme_query_swdb_result_t result = gpgme_op_query_swdb_result(ctx);
  while (result) {
      ret.push_back(SwdbResult(result));
      result = result->next;
  }

  gpgme_release(ctx);
  return ret;
}

std::ostream &GpgME::operator<<(std::ostream &os, const GpgME::SwdbResult &result)
{
    os << "GpgME::SwdbResult(";
    if (!result.isNull()) {
        os << "\n name: "     << result.name()
           << "\n version: "  << result.version()
           << "\n installed: "<< result.installedVersion()
           << "\n created: "  << result.created()
           << "\n retrieved: "<< result.retrieved()
           << "\n warning: "  << result.warning()
           << "\n update: "   << result.update()
           << "\n urgent: "   << result.urgent()
           << "\n noinfo: "   << result.noinfo()
           << "\n unknown: "  << result.unknown()
           << "\n tooOld: "   << result.tooOld()
           << "\n error: "    << result.error()
           << "\n reldate: "  << result.releaseDate()
           << '\n';
    }
    return os << ")\n";
}
