/*
  exception.cpp - exception wrapping a gpgme error
  Copyright (C) 2007 Klarälvdalens Datakonsult AB

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

// -*- c++ -*-
#include "exception.h"

#include <gpgme.h>

#include <sstream>

using namespace GpgME;
using namespace std; // only safe b/c it's so small a file!

Exception::~Exception() throw() {}

// static
string Exception::make_message(const Error &err, const string &msg)
{
    return make_message(err, msg, NoOptions);
}

// static
string Exception::make_message(const Error &err, const string &msg, Options opt)
{
    if (opt & MessageOnly) {
        return msg;
    }
    char error_string[128];
    error_string[0] = '\0';
    gpgme_strerror_r(err.encodedError(), error_string, sizeof error_string);
    error_string[sizeof error_string - 1] = '\0';
    stringstream ss;
    ss << gpgme_strsource(err.encodedError()) << ": ";
    if (!msg.empty()) {
        ss << msg << ": ";
    }
    ss << error_string << " (" << static_cast<unsigned long>(err.encodedError()) << ')';
    return ss.str();
}
