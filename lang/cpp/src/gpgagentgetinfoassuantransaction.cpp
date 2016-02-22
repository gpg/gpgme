/*
  gpgagentgetinfoassuantransaction.cpp - Assuan Transaction to get information from gpg-agent
  Copyright (C) 2009 Klarälvdalens Datakonsult AB

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

#include <config-gpgme++.h>

#include "gpgagentgetinfoassuantransaction.h"
#include "error.h"
#include "data.h"
#include "util.h"

#include <boost/static_assert.hpp>

#include <sstream>

using namespace GpgME;
using namespace boost;

GpgAgentGetInfoAssuanTransaction::GpgAgentGetInfoAssuanTransaction(InfoItem item)
    : AssuanTransaction(),
      m_item(item),
      m_command(),
      m_data()
{

}

GpgAgentGetInfoAssuanTransaction::~GpgAgentGetInfoAssuanTransaction() {}

std::string GpgAgentGetInfoAssuanTransaction::version() const
{
    if (m_item == Version) {
        return m_data;
    } else {
        return std::string();
    }
}

unsigned int GpgAgentGetInfoAssuanTransaction::pid() const
{
    if (m_item == Pid) {
        return to_pid(m_data);
    } else {
        return 0U;
    }
}

std::string GpgAgentGetInfoAssuanTransaction::socketName() const
{
    if (m_item == SocketName) {
        return m_data;
    } else {
        return std::string();
    }
}

std::string GpgAgentGetInfoAssuanTransaction::sshSocketName() const
{
    if (m_item == SshSocketName) {
        return m_data;
    } else {
        return std::string();
    }
}

static const char *const gpgagent_getinfo_tokens[] = {
    "version",
    "pid",
    "socket_name",
    "ssh_socket_name",
    "scd_running",
};
BOOST_STATIC_ASSERT((sizeof gpgagent_getinfo_tokens / sizeof * gpgagent_getinfo_tokens == GpgAgentGetInfoAssuanTransaction::LastInfoItem));

void GpgAgentGetInfoAssuanTransaction::makeCommand() const
{
    assert(m_item >= 0);
    assert(m_item < LastInfoItem);
    m_command = "GETINFO ";
    m_command += gpgagent_getinfo_tokens[m_item];
}

const char *GpgAgentGetInfoAssuanTransaction::command() const
{
    makeCommand();
    return m_command.c_str();
}

Error GpgAgentGetInfoAssuanTransaction::data(const char *data, size_t len)
{
    m_data.append(data, len);
    return Error();
}

Data GpgAgentGetInfoAssuanTransaction::inquire(const char *name, const char *args, Error &err)
{
    (void)name; (void)args; (void)err;
    return Data::null;
}

Error GpgAgentGetInfoAssuanTransaction::status(const char *status, const char *args)
{
    (void)status; (void)args;
    return Error();
}
