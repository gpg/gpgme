/*
  editinteractor.h - Interface for edit interactors
  Copyright (C) 2007 Klarälvdalens Datakonsult AB
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

#ifndef __GPGMEPP_EDITINTERACTOR_H__
#define __GPGMEPP_EDITINTERACTOR_H__

#include "gpgmepp_export.h"

#include <cstdio>

namespace GpgME
{

class Error;
class Context;
class CallbackHelper;

class GPGMEPP_EXPORT EditInteractor
{
    friend class ::GpgME::Context;
    friend class ::GpgME::CallbackHelper;
    EditInteractor(const EditInteractor &);
    EditInteractor &operator=(const EditInteractor &);
public:
    EditInteractor();
    virtual ~EditInteractor();

    enum {
        StartState = 0,
        ErrorState = 0xFFFFFFFF
    };

    virtual const char *action(Error &err) const = 0;
    virtual unsigned int nextState(unsigned int statusCode, const char *args, Error &err) const = 0;

    unsigned int state() const;
    Error lastError() const;
    bool needsNoResponse(unsigned int statusCode) const;

    void setDebugChannel(std::FILE *file);

private:
    class Private;
    Private *const d;
};

} // namespace GpgME

#endif // __GPGMEPP_EDITINTERACTOR_H__
