/*
  scdgetinfoassuantransaction.cpp - Assuan Transaction to get information from scdaemon
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

#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include "scdgetinfoassuantransaction.h"
#include "error.h"
#include "data.h"
#include "util.h"

#include <assert.h>

using namespace GpgME;

ScdGetInfoAssuanTransaction::ScdGetInfoAssuanTransaction(InfoItem item)
    : AssuanTransaction(),
      m_item(item),
      m_command(),
      m_data()
{

}

ScdGetInfoAssuanTransaction::~ScdGetInfoAssuanTransaction() {}

static std::vector<std::string> to_reader_list(const std::string &s)
{
    std::vector<std::string> result;
    std::stringstream ss(s);
    std::string tok;
    while (std::getline(ss, tok, '\n')) {
        result.push_back(tok);
    }
    return result;
}

static std::vector<std::string> to_app_list(const std::string &s)
{
    return to_reader_list(s);
}

std::string ScdGetInfoAssuanTransaction::version() const
{
    if (m_item == Version) {
        return m_data;
    } else {
        return std::string();
    }
}

unsigned int ScdGetInfoAssuanTransaction::pid() const
{
    if (m_item == Pid) {
        return to_pid(m_data);
    } else {
        return 0U;
    }
}

std::string ScdGetInfoAssuanTransaction::socketName() const
{
    if (m_item == SocketName) {
        return m_data;
    } else {
        return std::string();
    }
}

char ScdGetInfoAssuanTransaction::status() const
{
    if (m_item == Status && !m_data.empty()) {
        return m_data[0];
    } else {
        return '\0';
    }
}

std::vector<std::string> ScdGetInfoAssuanTransaction::readerList() const
{
    if (m_item == ReaderList) {
        return to_reader_list(m_data);
    } else {
        return std::vector<std::string>();
    }
}

std::vector<std::string> ScdGetInfoAssuanTransaction::applicationList() const
{
    if (m_item == ApplicationList) {
        return to_app_list(m_data);
    } else {
        return std::vector<std::string>();
    }
}

static const char *const scd_getinfo_tokens[] = {
    "version",
    "pid",
    "socket_name",
    "status",
    "reader_list",
    "deny_admin",
    "app_list",
};
static_assert((sizeof scd_getinfo_tokens / sizeof * scd_getinfo_tokens == ScdGetInfoAssuanTransaction::LastInfoItem),
              "getinfo_tokens size mismatch");

void ScdGetInfoAssuanTransaction::makeCommand() const
{
    assert(m_item >= 0);
    assert(m_item < LastInfoItem);
    m_command = "SCD GETINFO ";
    m_command += scd_getinfo_tokens[m_item];
}

const char *ScdGetInfoAssuanTransaction::command() const
{
    makeCommand();
    return m_command.c_str();
}

Error ScdGetInfoAssuanTransaction::data(const char *data, size_t len)
{
    m_data.append(data, len);
    return Error();
}

Data ScdGetInfoAssuanTransaction::inquire(const char *name, const char *args, Error &err)
{
    (void)name; (void)args; (void)err;
    return Data::null;
}

Error ScdGetInfoAssuanTransaction::status(const char *status, const char *args)
{
    (void)status; (void)args;
    return Error();
}
