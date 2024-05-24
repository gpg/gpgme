/*
  gpgagentgetinfoassuantransaction.h - Assuan Transaction to get information from gpg-agent
  Copyright (C) 2009 Klarälvdalens Datakonsult AB
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

#ifndef __GPGMEPP_GPGAGENTGETINFOASSUANTRANSACTION_H__
#define __GPGMEPP_GPGAGENTGETINFOASSUANTRANSACTION_H__

#include "interfaces/assuantransaction.h"

#include <string>
#include <vector>

namespace GpgME
{

class GPGMEPP_EXPORT GpgAgentGetInfoAssuanTransaction : public AssuanTransaction
{
public:
    enum InfoItem {
        Version,         // string
        Pid,             // unsigned long
        SocketName,      // string (path)
        SshSocketName,   // string (path)
        ScdRunning,      // (none, returns GPG_ERR_GENERAL when scdaemon isn't running)
        //CommandHasOption, // not supported

        LastInfoItem
    };

    explicit GpgAgentGetInfoAssuanTransaction(InfoItem item);
    ~GpgAgentGetInfoAssuanTransaction();

    std::string version() const;
    unsigned int pid() const;
    std::string socketName() const;
    std::string sshSocketName() const;

private:
    const char *command() const;
    Error data(const char *data, size_t datalen) override;
    Data inquire(const char *name, const char *args, Error &err) override;
    Error status(const char *status, const char *args) override;

private:
    void makeCommand() const;

private:
    InfoItem m_item;
    mutable std::string m_command;
    std::string m_data;
};

} // namespace GpgME

#endif // __GPGMEPP_GPGAGENTGETINFOASSUANTRANSACTION_H__
