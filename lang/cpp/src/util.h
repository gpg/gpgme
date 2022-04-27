/*
  util.h - some internal helpers
  Copyright (C) 2004 Klarälvdalens Datakonsult AB
  2016 Bundesamt für Sicherheit in der Informationstechnik
  Software engineering by Intevation GmbH
  Copyright (c) 2022 g10 Code GmbH
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
        oldmode |= GPGME_KEYLIST_MODE_SIG_NOTATIONS;
    }
    if (newmodes & GpgME::Validate) {
        oldmode |= GPGME_KEYLIST_MODE_VALIDATE;
    }
    if (newmodes & GpgME::Ephemeral) {
        oldmode |= GPGME_KEYLIST_MODE_EPHEMERAL;
    }
    if (newmodes & GpgME::WithTofu) {
        oldmode |= GPGME_KEYLIST_MODE_WITH_TOFU;
    }
    if (newmodes & GpgME::WithKeygrip) {
        oldmode |= GPGME_KEYLIST_MODE_WITH_KEYGRIP;
    }
    if (newmodes & GpgME::WithSecret) {
        oldmode |= GPGME_KEYLIST_MODE_WITH_SECRET;
    }
    if (newmodes & GpgME::ForceExtern) {
        oldmode |= GPGME_KEYLIST_MODE_FORCE_EXTERN;
    }
#ifndef NDEBUG
    if (newmodes & ~(GpgME::KeyListModeMask)) {
        //std::cerr << "GpgME::Context: keylist mode must be one of Local, "
        //"Extern, Signatures, SignatureNotations, Validate, Ephemeral, WithTofu, "
        //"WithKeygrip, WithSecret, ForceExtern, or a combination thereof!"
        //<< std::endl;
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
    if (mode & GPGME_KEYLIST_MODE_SIG_NOTATIONS) {
        result |= GpgME::SignatureNotations;
    }
    if (mode & GPGME_KEYLIST_MODE_WITH_SECRET) {
        result |= GpgME::WithSecret;
    }
    if (mode & GPGME_KEYLIST_MODE_WITH_TOFU) {
        result |= GpgME::WithTofu;
    }
    if (mode & GPGME_KEYLIST_MODE_WITH_KEYGRIP) {
        result |= GpgME::WithKeygrip;
    }
    if (mode & GPGME_KEYLIST_MODE_EPHEMERAL) {
        result |= GpgME::Ephemeral;
    }
    if (mode & GPGME_KEYLIST_MODE_VALIDATE) {
        result |= GpgME::Validate;
    }
    if (mode & GPGME_KEYLIST_MODE_FORCE_EXTERN) {
        result |= GpgME::ForceExtern;
    }
#ifndef NDEBUG
    if (mode & ~(GPGME_KEYLIST_MODE_LOCAL |
                 GPGME_KEYLIST_MODE_EXTERN |
                 GPGME_KEYLIST_MODE_SIGS |
                 GPGME_KEYLIST_MODE_SIG_NOTATIONS |
                 GPGME_KEYLIST_MODE_WITH_SECRET |
                 GPGME_KEYLIST_MODE_WITH_TOFU |
                 GPGME_KEYLIST_MODE_WITH_KEYGRIP |
                 GPGME_KEYLIST_MODE_EPHEMERAL |
                 GPGME_KEYLIST_MODE_VALIDATE |
                 GPGME_KEYLIST_MODE_FORCE_EXTERN)) {
        //std::cerr << "GpgME: WARNING: gpgme_get_keylist_mode() returned an unknown flag!" << std::endl;
    }
#endif // NDEBUG
    return result;
}

static inline GpgME::Notation::Flags convert_from_gpgme_sig_notation_flags_t(unsigned int flags)
{
    unsigned int result = 0;
    if (flags & GPGME_SIG_NOTATION_HUMAN_READABLE) {
        result |= GpgME::Notation::HumanReadable ;
    }
    if (flags & GPGME_SIG_NOTATION_CRITICAL) {
        result |= GpgME::Notation::Critical ;
    }
    return static_cast<GpgME::Notation::Flags>(result);
}

static inline gpgme_sig_notation_flags_t  add_to_gpgme_sig_notation_flags_t(unsigned int oldflags, unsigned int newflags)
{
    unsigned int result = oldflags;
    if (newflags & GpgME::Notation::HumanReadable) {
        result |= GPGME_SIG_NOTATION_HUMAN_READABLE;
    }
    if (newflags & GpgME::Notation::Critical) {
        result |= GPGME_SIG_NOTATION_CRITICAL;
    }
    return static_cast<gpgme_sig_notation_flags_t>(result);
}

static inline std::vector<std::string> split(const std::string &text, char delimiter)
{
    std::vector<std::string> result;
    if (!text.empty()) {
        std::istringstream stream{text};
        std::string line;
        while (std::getline(stream, line, delimiter)) {
            result.push_back(line);
        }
    }
    return result;
}

/**
 * Adapter for passing a vector of strings as NULL-terminated array of
 * const char* to the C-interface of gpgme.
 */
class StringsToCStrings
{
public:
    explicit StringsToCStrings(const std::vector<std::string> &v);
    ~StringsToCStrings() = default;

    StringsToCStrings(const StringsToCStrings &) = delete;
    StringsToCStrings &operator=(const StringsToCStrings &) = delete;
    StringsToCStrings(StringsToCStrings &&) = delete;
    StringsToCStrings &operator=(StringsToCStrings &&) = delete;

    const char **c_strs() const;
private:
    const std::vector<std::string> m_strings;
    mutable std::vector<const char *> m_cstrings;
};

#endif // __GPGMEPP_UTIL_H__
