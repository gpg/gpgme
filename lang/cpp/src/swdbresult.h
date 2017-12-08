/*
  swdbresult.h - wraps a gpgme swdb query / rsult
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
#ifndef __GPGMEPP_SWDB_H__
#define __GPGMEPP_SWDB_H__

#include "gpgmepp_export.h"

#include "global.h"
#include "engineinfo.h"

#include <vector>
#include <string>
#include <iostream>
#include <ostream>

namespace GpgME
{

class GPGMEPP_EXPORT SwdbResult
{
public:
    /* Obtain swdb results through query() */
    SwdbResult();
    explicit SwdbResult(gpgme_query_swdb_result_t result);

    /** Query the swdb to get information about updates.
     *
     * Runs gpgconf --query-swdb through gpgme and
     * returns a list of results.
     * If iversion is given as NULL a check is only done if GPGME
     * can figure out the version by itself (for example when using
     * "gpgme" or "gnupg").
     *
     * If NULL is used for name the current gpgme version is
     * checked.
     *
     * @param name: Name of the component to query.
     * @param iversion: Optionally the installed version.
     * @param err: Optional error.
     */
    static std::vector<SwdbResult> query(const char *name,
                                         const char *iversion = NULL,
                                         Error *err = NULL);

    const SwdbResult &operator=(SwdbResult other)
    {
        swap(other);
        return *this;
    }

    void swap(SwdbResult &other)
    {
        using std::swap;
        swap(this->d, other.d);
    }
    bool isNull() const;

    /* The name of the package (e.g. "gpgme", "gnupg") */
    std::string name() const;

    /* The version of the installed version.  */
    EngineInfo::Version installedVersion() const;

    /* The time the online info was created.  */
    unsigned long created() const;

    /* The time the online info was retrieved.  */
    unsigned long retrieved() const;

    /* This bit is set if an error occurred or some of the information
     * in this structure may not be set.  */
    bool warning() const;

    /* An update is available.  */
    bool update() const;

    /* The update is important.  */
    bool urgent() const;

    /* No information at all available.  */
    bool noinfo() const;

    /* The package name is not known. */
    bool unknown() const;

    /* The information here is too old.  */
    bool tooOld() const;

    /* Other error.  */
    bool error() const;

    /* The version of the latest released version.  */
    EngineInfo::Version version() const;

    /* The release date of that version.  */
    unsigned long releaseDate() const;

private:
    class Private;
    std::shared_ptr<Private> d;
};

GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, const SwdbResult &info);

} // namespace GpgME

GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(SwdbResult)

#endif
