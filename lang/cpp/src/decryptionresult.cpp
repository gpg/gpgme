/*
  decryptionresult.cpp - wraps a gpgme keygen result
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

#include <config-gpgme++.h>

#include <decryptionresult.h>
#include "result_p.h"
#include "util.h"

#include <gpgme.h>

#include <algorithm>
#include <iterator>
#include <cstring>
#include <cstdlib>
#include <istream>

#include <string.h>

class GpgME::DecryptionResult::Private
{
public:
    explicit Private(const _gpgme_op_decrypt_result &r) : res(r)
    {
        if (res.unsupported_algorithm) {
            res.unsupported_algorithm = strdup(res.unsupported_algorithm);
        }
#ifdef HAVE_GPGME_DECRYPT_RESULT_T_FILE_NAME
        if (res.file_name) {
            res.file_name = strdup(res.file_name);
        }
#endif
#ifdef HAVE_GPGME_DECRYPT_RESULT_T_RECIPIENTS
        //FIXME: copying gpgme_recipient_t objects invalidates the keyid member,
        //thus we use _keyid for now (internal API)
        for (gpgme_recipient_t r = res.recipients ; r ; r = r->next) {
            recipients.push_back(*r);
        }
        res.recipients = 0;
#endif
    }
    ~Private()
    {
        if (res.unsupported_algorithm) {
            std::free(res.unsupported_algorithm);
        }
        res.unsupported_algorithm = 0;
#ifdef HAVE_GPGME_DECRYPT_RESULT_T_FILE_NAME
        if (res.file_name) {
            std::free(res.file_name);
        }
        res.file_name = 0;
#endif
    }

    _gpgme_op_decrypt_result res;
#ifdef HAVE_GPGME_DECRYPT_RESULT_T_RECIPIENTS
    std::vector<_gpgme_recipient> recipients;
#endif
};

GpgME::DecryptionResult::DecryptionResult(gpgme_ctx_t ctx, int error)
    : GpgME::Result(error), d()
{
    init(ctx);
}

GpgME::DecryptionResult::DecryptionResult(gpgme_ctx_t ctx, const Error &error)
    : GpgME::Result(error), d()
{
    init(ctx);
}

void GpgME::DecryptionResult::init(gpgme_ctx_t ctx)
{
    if (!ctx) {
        return;
    }
    gpgme_decrypt_result_t res = gpgme_op_decrypt_result(ctx);
    if (!res) {
        return;
    }
    d.reset(new Private(*res));
}

make_standard_stuff(DecryptionResult)

const char *GpgME::DecryptionResult::unsupportedAlgorithm() const
{
    return d ? d->res.unsupported_algorithm : 0 ;
}

bool GpgME::DecryptionResult::isWrongKeyUsage() const
{
    return d && d->res.wrong_key_usage;
}

const char *GpgME::DecryptionResult::fileName() const
{
#ifdef HAVE_GPGME_DECRYPT_RESULT_T_FILE_NAME
    return d ? d->res.file_name : 0 ;
#else
    return 0;
#endif
}

unsigned int GpgME::DecryptionResult::numRecipients() const
{
#ifdef HAVE_GPGME_DECRYPT_RESULT_T_RECIPIENTS
    return d ? d->recipients.size() : 0 ;
#else
    return 0;
#endif
}

GpgME::DecryptionResult::Recipient GpgME::DecryptionResult::recipient(unsigned int idx) const
{
#ifdef HAVE_GPGME_DECRYPT_RESULT_T_RECIPIENTS
    if (d && idx < d->recipients.size()) {
        return Recipient(&d->recipients[idx]);
    }
#endif
    return Recipient();
}

namespace
{
struct make_recipient {
    GpgME::DecryptionResult::Recipient operator()(_gpgme_recipient &t)
    {
        return GpgME::DecryptionResult::Recipient(&t);
    }
};
}

std::vector<GpgME::DecryptionResult::Recipient> GpgME::DecryptionResult::recipients() const
{
    std::vector<Recipient> result;
#ifdef HAVE_GPGME_DECRYPT_RESULT_T_RECIPIENTS
    if (d) {
        result.reserve(d->recipients.size());
        std::transform(d->recipients.begin(), d->recipients.end(),
                       std::back_inserter(result),
                       make_recipient());
    }
#endif
    return result;
}

#ifdef HAVE_GPGME_DECRYPT_RESULT_T_RECIPIENTS
class GpgME::DecryptionResult::Recipient::Private : public _gpgme_recipient
{
public:
    Private(gpgme_recipient_t reci) : _gpgme_recipient(*reci) {}
};
#endif

GpgME::DecryptionResult::Recipient::Recipient()
    : d()
{

}

GpgME::DecryptionResult::Recipient::Recipient(gpgme_recipient_t r)
    : d()
{
#ifdef HAVE_GPGME_DECRYPT_RESULT_T_RECIPIENTS
    if (r) {
        d.reset(new Private(r));
    }
#endif
}

bool GpgME::DecryptionResult::Recipient::isNull() const
{
    return !d;
}

const char *GpgME::DecryptionResult::Recipient::keyID() const
{
#ifdef HAVE_GPGME_DECRYPT_RESULT_T_RECIPIENTS
    //_keyid is internal API, but the public keyid is invalid after copying (see above)
    if (d) {
        return d->_keyid;
    }
#endif
    return 0;
}

const char *GpgME::DecryptionResult::Recipient::shortKeyID() const
{
#ifdef HAVE_GPGME_DECRYPT_RESULT_T_RECIPIENTS
    //_keyid is internal API, but the public keyid is invalid after copying (see above)
    if (d) {
        return d->_keyid + 8;
    }
#endif
    return 0;
}

unsigned int GpgME::DecryptionResult::Recipient::publicKeyAlgorithm() const
{
#ifdef HAVE_GPGME_DECRYPT_RESULT_T_RECIPIENTS
    if (d) {
        return d->pubkey_algo;
    }
#endif
    return 0;
}

const char *GpgME::DecryptionResult::Recipient::publicKeyAlgorithmAsString() const
{
#ifdef HAVE_GPGME_DECRYPT_RESULT_T_RECIPIENTS
    if (d) {
        return gpgme_pubkey_algo_name(d->pubkey_algo);
    }
#endif
    return 0;
}

GpgME::Error GpgME::DecryptionResult::Recipient::status() const
{
#ifdef HAVE_GPGME_DECRYPT_RESULT_T_RECIPIENTS
    if (d) {
        return Error(d->status);
    }
#endif
    return Error();
}

std::ostream &GpgME::operator<<(std::ostream &os, const DecryptionResult &result)
{
    os << "GpgME::DecryptionResult(";
    if (!result.isNull()) {
        os << "\n error:                " << result.error()
           << "\n fileName:             " << protect(result.fileName())
           << "\n unsupportedAlgorithm: " << protect(result.unsupportedAlgorithm())
           << "\n isWrongKeyUsage:      " << result.isWrongKeyUsage()
           << "\n recipients:\n";
        const std::vector<DecryptionResult::Recipient> recipients = result.recipients();
        std::copy(recipients.begin(), recipients.end(),
                  std::ostream_iterator<DecryptionResult::Recipient>(os, "\n"));
    }
    return os << ')';
}

std::ostream &GpgME::operator<<(std::ostream &os, const DecryptionResult::Recipient &reci)
{
    os << "GpgME::DecryptionResult::Recipient(";
    if (!reci.isNull()) {
        os << "\n keyID:              " << protect(reci.keyID())
           << "\n shortKeyID:         " << protect(reci.shortKeyID())
           << "\n publicKeyAlgorithm: " << protect(reci.publicKeyAlgorithmAsString())
           << "\n status:             " << reci.status();
    }
    return os << ')';
}
