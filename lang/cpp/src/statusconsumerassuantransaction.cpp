/*
  statusconsumerassuantransaction.cpp
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

#include "statusconsumerassuantransaction.h"

#include "data.h"
#include "error.h"

#include "interfaces/statusconsumer.h"

using namespace GpgME;

StatusConsumerAssuanTransaction::StatusConsumerAssuanTransaction(StatusConsumer *statusConsumer)
    : AssuanTransaction()
    , m_consumer(statusConsumer)
{
}

StatusConsumerAssuanTransaction::~StatusConsumerAssuanTransaction()
{
}

Error StatusConsumerAssuanTransaction::data(const char *data, size_t datalen)
{
    (void) data;
    (void) datalen;
    return Error();
}

Data StatusConsumerAssuanTransaction::inquire(const char *name, const char *args, Error &err)
{
    (void)name;
    (void)args;
    (void)err;
    return Data::null;
}

Error StatusConsumerAssuanTransaction::status(const char *status, const char *args)
{
    m_consumer->status(status, args);

    return Error();
}
