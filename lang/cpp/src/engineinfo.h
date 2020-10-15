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

#ifndef __GPGMEPP_ENGINEINFO_H__
#define __GPGMEPP_ENGINEINFO_H__

#include "global.h"

#include <memory>

#include <algorithm>
#include <string>
#include <iostream>

namespace GpgME
{

class GPGMEPP_EXPORT EngineInfo
{
public:
    struct Version
    {
        int major, minor, patch;
        Version()
        {
          major = 0;
          minor = 0;
          patch = 0;
        }

        Version(const std::string& version)
        {
            if (version.empty() ||
                std::sscanf(version.c_str(), "%d.%d.%d", &major, &minor, &patch) != 3) {
                major = 0;
                minor = 0;
                patch = 0;
            }
        }

        Version(const char *version)
        {
            if (!version ||
                std::sscanf(version, "%d.%d.%d", &major, &minor, &patch) != 3) {
                major = 0;
                minor = 0;
                patch = 0;
            }
        }

        bool operator < (const Version& other)
        {
            if (major > other.major ||
                (major == other.major && minor > other.minor) ||
                (major == other.major && minor == other.minor && patch > other.patch) ||
                (major >= other.major && minor >= other.minor && patch >= other.patch)) {
                return false;
            }
            return true;
        }

        bool operator < (const char* other)
        {
            return operator<(Version(other));
        }

        bool operator <= (const Version &other)
        {
            return !operator>(other);
        }

        bool operator <= (const char *other)
        {
            return operator<=(Version(other));
        }

        bool operator > (const char* other)
        {
            return operator>(Version(other));
        }

        bool operator > (const Version & other)
        {
            return !operator<(other) && !operator==(other);
        }

        bool operator >= (const Version &other)
        {
            return !operator<(other);
        }

        bool operator >= (const char *other)
        {
            return operator>=(Version(other));
        }

        bool operator == (const Version& other)
        {
            return major == other.major
                && minor == other.minor
                && patch == other.patch;
        }

        bool operator == (const char* other)
        {
            return operator==(Version(other));
        }

        bool operator != (const Version &other)
        {
            return !operator==(other);
        }

        bool operator != (const char *other)
        {
            return operator!=(Version(other));
        }

        friend std::ostream& operator << (std::ostream& stream, const Version& ver)
        {
            stream << ver.major;
            stream << '.';
            stream << ver.minor;
            stream << '.';
            stream << ver.patch;
            return stream;
        }
    };

    EngineInfo();
    explicit EngineInfo(gpgme_engine_info_t engine);

    const EngineInfo &operator=(EngineInfo other)
    {
        swap(other);
        return *this;
    }

    void swap(EngineInfo &other)
    {
        using std::swap;
        swap(this->d, other.d);
    }

    bool isNull() const;

    Protocol protocol() const;
    const char *fileName() const;
    const char *version() const;
    Version engineVersion() const;
    const char *requiredVersion() const;
    const char *homeDirectory() const;

private:
    class Private;
    std::shared_ptr<Private> d;
};

}

GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(EngineInfo)

#endif // __GPGMEPP_ENGINEINFO_H__
