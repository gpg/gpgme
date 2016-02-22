/*
  util.h - some inline helper functions
  Copyright (C) 2004 Klarälvdalens Datakonsult AB

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
#ifndef __GPGMEPP_UTIL_H__
#define __GPGMEPP_UTIL_H__

#include "global.h"
#include "notation.h"

#include <gpgme.h>

#ifndef NDEBUG
#include <iostream>
#endif
#include <sstream>
#include <string>

static inline const char *protect(const char *s)
{
    return s ? s : "<null>" ;
}

static inline gpgme_error_t make_error(gpgme_err_code_t code)
{
    return gpgme_err_make((gpgme_err_source_t)22, code);
}

static inline unsigned long to_pid(const std::string &s)
{
    std::stringstream ss(s);
    unsigned int result;
    if (ss >> result) {
        return result;
    } else {
        return 0U;
    }
}

static inline gpgme_keylist_mode_t add_to_gpgme_keylist_mode_t(unsigned int oldmode, unsigned int newmodes)
{
    if (newmodes & GpgME::Local) {
        oldmode |= GPGME_KEYLIST_MODE_LOCAL;
    }
    if (newmodes & GpgME::Extern) {
        oldmode |= GPGME_KEYLIST_MODE_EXTERN;
    }
    if (newmodes & GpgME::Signatures) {
        oldmode |= GPGME_KEYLIST_MODE_SIGS;
    }
    if (newmodes & GpgME::SignatureNotations) {
#ifdef HAVE_GPGME_KEYLIST_MODE_SIG_NOTATIONS
        oldmode |= GPGME_KEYLIST_MODE_SIG_NOTATIONS;
#elif !defined(NDEBUG)
        ;//std::cerr << "GpgME: ignoring SignatureNotations keylist flag (gpgme too old)." << std::endl;
#endif
    }
    if (newmodes & GpgME::Ephemeral) {
#ifdef HAVE_GPGME_KEYLIST_MODE_EPHEMERAL
        oldmode |= GPGME_KEYLIST_MODE_EPHEMERAL;
#elif !defined(NDEBUG)
        ;//std::cerr << "GpgME: ignoring Ephemeral keylist flag (gpgme too old)." << std::endl;
#endif
    }
    if (newmodes & GpgME::Validate) {
        oldmode |= GPGME_KEYLIST_MODE_VALIDATE;
    }
#ifndef NDEBUG
    if (newmodes & ~(GpgME::Local | GpgME::Extern | GpgME::Signatures | GpgME::SignatureNotations | GpgME::Ephemeral | GpgME::Validate)) {
        //std::cerr << "GpgME::Context: keylist mode must be one of Local, "
        //"Extern, Signatures, SignatureNotations, or Validate, or a combination thereof!" << std::endl;
    }
#endif
    return static_cast<gpgme_keylist_mode_t>(oldmode);
}

static inline unsigned int convert_from_gpgme_keylist_mode_t(unsigned int mode)
{
    unsigned int result = 0;
    if (mode & GPGME_KEYLIST_MODE_LOCAL) {
        result |= GpgME::Local;
    }
    if (mode & GPGME_KEYLIST_MODE_EXTERN) {
        result |= GpgME::Extern;
    }
    if (mode & GPGME_KEYLIST_MODE_SIGS) {
        result |= GpgME::Signatures;
    }
#ifdef HAVE_GPGME_KEYLIST_MODE_SIG_NOTATIONS
    if (mode & GPGME_KEYLIST_MODE_SIG_NOTATIONS) {
        result |= GpgME::SignatureNotations;
    }
#endif
#ifdef HAVE_GPGME_KEYLIST_MODE_EPHEMERAL
    if (mode & GPGME_KEYLIST_MODE_EPHEMERAL) {
        result |= GpgME::Ephemeral;
    }
#endif
    if (mode & GPGME_KEYLIST_MODE_VALIDATE) {
        result |= GpgME::Validate;
    }
#ifndef NDEBUG
    if (mode & ~(GPGME_KEYLIST_MODE_LOCAL |
                 GPGME_KEYLIST_MODE_EXTERN |
#ifdef HAVE_GPGME_KEYLIST_MODE_SIG_NOTATIONS
                 GPGME_KEYLIST_MODE_SIG_NOTATIONS |
#endif
#ifdef HAVE_GPGME_KEYLIST_MODE_EPHEMERAL
                 GPGME_KEYLIST_MODE_EPHEMERAL |
#endif
                 GPGME_KEYLIST_MODE_VALIDATE |
                 GPGME_KEYLIST_MODE_SIGS)) {
        //std::cerr << "GpgME: WARNING: gpgme_get_keylist_mode() returned an unknown flag!" << std::endl;
    }
#endif // NDEBUG
    return result;
}

static inline GpgME::Notation::Flags convert_from_gpgme_sig_notation_flags_t(unsigned int flags)
{
#ifdef HAVE_GPGME_SIG_NOTATION_FLAGS_T
    unsigned int result = 0;
#ifdef HAVE_GPGME_SIG_NOTATION_HUMAN_READABLE
    if (flags & GPGME_SIG_NOTATION_HUMAN_READABLE) {
        result |= GpgME::Notation::HumanReadable ;
    }
#endif
#ifdef HAVE_GPGME_SIG_NOTATION_CRITICAL
    if (flags & GPGME_SIG_NOTATION_CRITICAL) {
        result |= GpgME::Notation::Critical ;
    }
#endif
    return static_cast<GpgME::Notation::Flags>(result);
#else
    return GpgME::Notation::NoFlags;
#endif
}
#ifdef HAVE_GPGME_SIG_NOTATION_FLAGS_T
static inline gpgme_sig_notation_flags_t  add_to_gpgme_sig_notation_flags_t(unsigned int oldflags, unsigned int newflags)
{
    unsigned int result = oldflags;
    if (newflags & GpgME::Notation::HumanReadable) {
#ifdef HAVE_GPGME_SIG_NOTATION_HUMAN_READABLE
        result |= GPGME_SIG_NOTATION_HUMAN_READABLE;
#elif !defined(NDEBUG)
        //std::cerr << "GpgME::Context: ignoring HumanReadable signature notation flag (gpgme too old)" << std::endl;
#endif
    }
    if (newflags & GpgME::Notation::Critical) {
#ifdef HAVE_GPGME_SIG_NOTATION_CRITICAL
        result |= GPGME_SIG_NOTATION_CRITICAL;
#elif !defined(NDEBUG)
        //std::cerr << "GpgME::Context: ignoring Critical signature notation flag (gpgme too old)" << std::endl;
#endif
    }
    return static_cast<gpgme_sig_notation_flags_t>(result);
}
#endif

#endif // __GPGMEPP_UTIL_H__
