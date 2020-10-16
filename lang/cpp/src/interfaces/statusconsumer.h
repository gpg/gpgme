/*
  statusconsumer.h - Interface for status callbacks
  Copyright (c) 2020 g10 Code GmbH
  Software engineering by Ingo Klöcker <dev@ingo-kloecker.de>

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

#ifndef __GPGMEPP_INTERFACES_STATUSCONSUMER_H__
#define __GPGMEPP_INTERFACES_STATUSCONSUMER_H__

#include "gpgmepp_export.h"

namespace GpgME
{

class GPGMEPP_EXPORT StatusConsumer
{
public:
    virtual ~StatusConsumer() {}

    virtual void status(const char *status, const char *details) = 0;
};

} // namespace GpgME

#endif // __GPGMEPP_INTERFACES_STATUSCONSUMER_H__
