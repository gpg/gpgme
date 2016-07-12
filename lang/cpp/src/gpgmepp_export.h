/*gpgmepp_export.h - Export macros for gpgmepp
  Copyright (C) 2016, Intevation GmbH

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

#ifndef GPGMEPP_EXPORT_H
#define GPGMEPP_EXPORT_H

#ifdef GPGMEPP_STATIC_DEFINE
#  define GPGMEPP_EXPORT
#  define GPGMEPP_NO_EXPORT
#else
#  ifndef GPGMEPP_EXPORT
#    ifdef BUILDING_GPGMEPP
        /* We are building this library */
#      ifdef WIN32
#       define GPGMEPP_EXPORT __declspec(dllexport)
#      else
#       define GPGMEPP_EXPORT __attribute__((visibility("default")))
#      endif
#    else
        /* We are using this library */
#      ifdef WIN32
#       define GPGMEPP_EXPORT __declspec(dllimport)
#      else
#       define GPGMEPP_EXPORT __attribute__((visibility("default")))
#      endif
#    endif
#  endif

#  ifndef GPGMEPP_NO_EXPORT
#    ifdef WIN32
#     define GPGMEPP_NO_EXPORT
#    else
#     define GPGMEPP_NO_EXPORT __attribute__((visibility("hidden")))
#    endif
#  endif
#endif

#ifndef GPGMEPP_DEPRECATED
#  define GPGMEPP_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef GPGMEPP_DEPRECATED_EXPORT
#  define GPGMEPP_DEPRECATED_EXPORT GPGMEPP_EXPORT GPGMEPP_DEPRECATED
#endif

#ifndef GPGMEPP_DEPRECATED_NO_EXPORT
#  define GPGMEPP_DEPRECATED_NO_EXPORT GPGMEPP_NO_EXPORT GPGMEPP_DEPRECATED
#endif

#define DEFINE_NO_DEPRECATED 0
#if DEFINE_NO_DEPRECATED
# define GPGMEPP_NO_DEPRECATED
#endif

#endif
