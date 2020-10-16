/*
  statusconsumerassuantransaction.h - Assuan transaction that forwards status lines to a consumer
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

#ifndef __GPGMEPP_STATUSCONSUMERASSUANTRANSACTION_H__
#define __GPGMEPP_STATUSCONSUMERASSUANTRANSACTION_H__

#include <interfaces/assuantransaction.h>

namespace GpgME
{

class StatusConsumer;

class GPGMEPP_EXPORT StatusConsumerAssuanTransaction: public AssuanTransaction
{
public:
    explicit StatusConsumerAssuanTransaction(StatusConsumer *statusConsumer);
    ~StatusConsumerAssuanTransaction();

private:
    Error data(const char *data, size_t datalen) override;
    Data inquire(const char *name, const char *args, Error &err) override;
    Error status(const char *status, const char *args) override;

private:
    StatusConsumer *m_consumer;
};

} // namespace GpgME

#endif // __GPGMEPP_STATUSCONSUMERASSUANTRANSACTION_H__
