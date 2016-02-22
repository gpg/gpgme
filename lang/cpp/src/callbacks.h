/*
  callbacks.h - callback targets for internal use:
  Copyright (C) 2003 Klarälvdalens Datakonsult AB

  This file is part of GPGME++.

  This is an internal header file, subject to change without
  notice. DO NOT USE.

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

#ifndef __GPGMEPP_CALLBACKS_H__
#define __GPGMEPP_CALLBACKS_H__

#include <gpgme.h>

extern "C" {

    void progress_callback(void *opaque, const char *what,
                           int type, int current, int total);
    gpgme_error_t passphrase_callback(void *opaque, const char *uid_hint,
                                      const char *desc, int prev_was_bad, int fd);
}

namespace GpgME
{
extern const gpgme_data_cbs data_provider_callbacks;
extern const gpgme_edit_cb_t edit_interactor_callback;
}

#endif // __GPGME_CALLBACKS_H__
