/*
  decryptionresult.cpp - wraps a gpgme keygen result
  Copyright (C) 2004 Klarälvdalens Datakonsult AB
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
        if (res.file_name) {
            res.file_name = strdup(res.file_name);
        }
        if (res.symkey_algo) {
            res.symkey_algo = strdup(res.symkey_algo);
        }
        //FIXME: copying gpgme_recipient_t objects invalidates the keyid member,
        //thus we use _keyid for now (internal API)
        for (gpgme_recipient_t r = res.recipients ; r ; r = r->next) {
            recipients.push_back(*r);
        }
        res.recipients = nullptr;
    }
    ~Private()
    {
        if (res.unsupported_algorithm) {
            std::free(res.unsupported_algorithm);
        }
        res.unsupported_algorithm = nullptr;
        if (res.file_name) {
            std::free(res.file_name);
        }
        res.file_name = nullptr;
        if (res.symkey_algo) {
            std::free(res.symkey_algo);
        }
        res.symkey_algo = nullptr;
    }

    _gpgme_op_decrypt_result res;
    std::vector<_gpgme_recipient> recipients;
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
    return d ? d->res.unsupported_algorithm : nullptr ;
}

bool GpgME::DecryptionResult::isWrongKeyUsage() const
{
    return d && d->res.wrong_key_usage;
}

bool GpgME::DecryptionResult::isDeVs() const
{
    return d && d->res.is_de_vs;
}

bool GpgME::DecryptionResult::isMime() const
{
    return d && d->res.is_mime;
}

const char *GpgME::DecryptionResult::fileName() const
{
    return d ? d->res.file_name : nullptr ;
}

unsigned int GpgME::DecryptionResult::numRecipients() const
{
    return d ? d->recipients.size() : 0 ;
}

GpgME::DecryptionResult::Recipient GpgME::DecryptionResult::recipient(unsigned int idx) const
{
    if (d && idx < d->recipients.size()) {
        return Recipient(&d->recipients[idx]);
    }
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
    if (d) {
        result.reserve(d->recipients.size());
        std::transform(d->recipients.begin(), d->recipients.end(),
                       std::back_inserter(result),
                       make_recipient());
    }
    return result;
}

const char *GpgME::DecryptionResult::sessionKey() const
{
  return d ? d->res.session_key : nullptr;
}

const char *GpgME::DecryptionResult::symkeyAlgo() const
{
  return d ? d->res.symkey_algo : nullptr;
}

bool GpgME::DecryptionResult::isLegacyCipherNoMDC() const
{
  return d && d->res.legacy_cipher_nomdc;
}

class GpgME::DecryptionResult::Recipient::Private : public _gpgme_recipient
{
public:
    Private(gpgme_recipient_t reci) : _gpgme_recipient(*reci) {}
};

GpgME::DecryptionResult::Recipient::Recipient()
    : d()
{

}

GpgME::DecryptionResult::Recipient::Recipient(gpgme_recipient_t r)
    : d()
{
    if (r) {
        d.reset(new Private(r));
    }
}

bool GpgME::DecryptionResult::Recipient::isNull() const
{
    return !d;
}

const char *GpgME::DecryptionResult::Recipient::keyID() const
{
    //_keyid is internal API, but the public keyid is invalid after copying (see above)
    if (d) {
        return d->_keyid;
    }
    return nullptr;
}

const char *GpgME::DecryptionResult::Recipient::shortKeyID() const
{
    //_keyid is internal API, but the public keyid is invalid after copying (see above)
    if (d) {
        return d->_keyid + 8;
    }
    return nullptr;
}

unsigned int GpgME::DecryptionResult::Recipient::publicKeyAlgorithm() const
{
    if (d) {
        return d->pubkey_algo;
    }
    return 0;
}

const char *GpgME::DecryptionResult::Recipient::publicKeyAlgorithmAsString() const
{
    if (d) {
        return gpgme_pubkey_algo_name(d->pubkey_algo);
    }
    return nullptr;
}

GpgME::Error GpgME::DecryptionResult::Recipient::status() const
{
    if (d) {
        return Error(d->status);
    }
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
           << "\n isDeVs                " << result.isDeVs()
           << "\n legacyCipherNoMDC     " << result.isLegacyCipherNoMDC()
           << "\n symkeyAlgo:           " << protect(result.symkeyAlgo())
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
