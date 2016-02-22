/*
  data_p.h - wraps a gpgme data object, private part -*- c++ -*-
  Copyright (C) 2003,2004 Klarälvdalens Datakonsult AB

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

#ifndef __GPGMEPP_DATA_P_H__
#define __GPGMEPP_DATA_P_H__

#include <data.h>
#include "callbacks.h"

class GpgME::Data::Private
{
public:
    explicit Private(gpgme_data_t d = 0)
        : data(d), cbs(data_provider_callbacks) {}
    ~Private();

    gpgme_data_t data;
    gpgme_data_cbs cbs;
};

#endif // __GPGMEPP_DATA_P_H__
