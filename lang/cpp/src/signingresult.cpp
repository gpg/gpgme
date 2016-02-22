/*
  signingresult.cpp - wraps a gpgme verify result
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

#include <signingresult.h>
#include "result_p.h"
#include "util.h"

#include <gpgme.h>

#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <istream>
#include <iterator>

#include <string.h>

class GpgME::SigningResult::Private
{
public:
    Private(const gpgme_sign_result_t r)
    {
        if (!r) {
            return;
        }
        for (gpgme_new_signature_t is = r->signatures ; is ; is = is->next) {
            gpgme_new_signature_t copy = new _gpgme_new_signature(*is);
            if (is->fpr) {
                copy->fpr = strdup(is->fpr);
            }
            copy->next = 0;
            created.push_back(copy);
        }
        for (gpgme_invalid_key_t ik = r->invalid_signers ; ik ; ik = ik->next) {
            gpgme_invalid_key_t copy = new _gpgme_invalid_key(*ik);
            if (ik->fpr) {
                copy->fpr = strdup(ik->fpr);
            }
            copy->next = 0;
            invalid.push_back(copy);
        }
    }
    ~Private()
    {
        for (std::vector<gpgme_new_signature_t>::iterator it = created.begin() ; it != created.end() ; ++it) {
            std::free((*it)->fpr);
            delete *it; *it = 0;
        }
        for (std::vector<gpgme_invalid_key_t>::iterator it = invalid.begin() ; it != invalid.end() ; ++it) {
            std::free((*it)->fpr);
            delete *it; *it = 0;
        }
    }

    std::vector<gpgme_new_signature_t> created;
    std::vector<gpgme_invalid_key_t> invalid;
};

GpgME::SigningResult::SigningResult(gpgme_ctx_t ctx, int error)
    : GpgME::Result(error), d()
{
    init(ctx);
}

GpgME::SigningResult::SigningResult(gpgme_ctx_t ctx, const Error &error)
    : GpgME::Result(error), d()
{
    init(ctx);
}

void GpgME::SigningResult::init(gpgme_ctx_t ctx)
{
    if (!ctx) {
        return;
    }
    gpgme_sign_result_t res = gpgme_op_sign_result(ctx);
    if (!res) {
        return;
    }
    d.reset(new Private(res));
}

make_standard_stuff(SigningResult)

GpgME::CreatedSignature GpgME::SigningResult::createdSignature(unsigned int idx) const
{
    return CreatedSignature(d, idx);
}

std::vector<GpgME::CreatedSignature> GpgME::SigningResult::createdSignatures() const
{
    if (!d) {
        return std::vector<CreatedSignature>();
    }
    std::vector<CreatedSignature> result;
    result.reserve(d->created.size());
    for (unsigned int i = 0 ; i < d->created.size() ; ++i) {
        result.push_back(CreatedSignature(d, i));
    }
    return result;
}

GpgME::InvalidSigningKey GpgME::SigningResult::invalidSigningKey(unsigned int idx) const
{
    return InvalidSigningKey(d, idx);
}

std::vector<GpgME::InvalidSigningKey> GpgME::SigningResult::invalidSigningKeys() const
{
    if (!d) {
        return std::vector<GpgME::InvalidSigningKey>();
    }
    std::vector<GpgME::InvalidSigningKey> result;
    result.reserve(d->invalid.size());
    for (unsigned int i = 0 ; i < d->invalid.size() ; ++i) {
        result.push_back(InvalidSigningKey(d, i));
    }
    return result;
}

GpgME::InvalidSigningKey::InvalidSigningKey(const boost::shared_ptr<SigningResult::Private> &parent, unsigned int i)
    : d(parent), idx(i)
{

}

GpgME::InvalidSigningKey::InvalidSigningKey() : d(), idx(0) {}

bool GpgME::InvalidSigningKey::isNull() const
{
    return !d || idx >= d->invalid.size() ;
}

const char *GpgME::InvalidSigningKey::fingerprint() const
{
    return isNull() ? 0 : d->invalid[idx]->fpr ;
}

GpgME::Error GpgME::InvalidSigningKey::reason() const
{
    return Error(isNull() ? 0 : d->invalid[idx]->reason);
}

GpgME::CreatedSignature::CreatedSignature(const boost::shared_ptr<SigningResult::Private> &parent, unsigned int i)
    : d(parent), idx(i)
{

}

GpgME::CreatedSignature::CreatedSignature() : d(), idx(0) {}

bool GpgME::CreatedSignature::isNull() const
{
    return !d || idx >= d->created.size() ;
}

const char *GpgME::CreatedSignature::fingerprint() const
{
    return isNull() ? 0 : d->created[idx]->fpr ;
}

time_t GpgME::CreatedSignature::creationTime() const
{
    return static_cast<time_t>(isNull() ? 0 : d->created[idx]->timestamp);
}

GpgME::SignatureMode GpgME::CreatedSignature::mode() const
{
    if (isNull()) {
        return NormalSignatureMode;
    }
    switch (d->created[idx]->type) {
    default:
    case GPGME_SIG_MODE_NORMAL: return NormalSignatureMode;
    case GPGME_SIG_MODE_DETACH: return Detached;
    case GPGME_SIG_MODE_CLEAR:  return Clearsigned;
    }
}

unsigned int GpgME::CreatedSignature::publicKeyAlgorithm() const
{
    return isNull() ? 0 : d->created[idx]->pubkey_algo ;
}

const char *GpgME::CreatedSignature::publicKeyAlgorithmAsString() const
{
    return gpgme_pubkey_algo_name(isNull() ? (gpgme_pubkey_algo_t)0 : d->created[idx]->pubkey_algo);
}

unsigned int GpgME::CreatedSignature::hashAlgorithm() const
{
    return isNull() ? 0 : d->created[idx]->hash_algo ;
}

const char *GpgME::CreatedSignature::hashAlgorithmAsString() const
{
    return gpgme_hash_algo_name(isNull() ? (gpgme_hash_algo_t)0 : d->created[idx]->hash_algo);
}

unsigned int GpgME::CreatedSignature::signatureClass() const
{
    return isNull() ? 0 : d->created[idx]->sig_class ;
}

std::ostream &GpgME::operator<<(std::ostream &os, const SigningResult &result)
{
    os << "GpgME::SigningResult(";
    if (!result.isNull()) {
        os << "\n error:              " << result.error()
           << "\n createdSignatures:\n";
        const std::vector<CreatedSignature> cs = result.createdSignatures();
        std::copy(cs.begin(), cs.end(),
                  std::ostream_iterator<CreatedSignature>(os, "\n"));
        os << " invalidSigningKeys:\n";
        const std::vector<InvalidSigningKey> isk = result.invalidSigningKeys();
        std::copy(isk.begin(), isk.end(),
                  std::ostream_iterator<InvalidSigningKey>(os, "\n"));
    }
    return os << ')';
}

std::ostream &GpgME::operator<<(std::ostream &os, const CreatedSignature &sig)
{
    os << "GpgME::CreatedSignature(";
    if (!sig.isNull()) {
        os << "\n fingerprint:        " << protect(sig.fingerprint())
           << "\n creationTime:       " << sig.creationTime()
           << "\n mode:               " << sig.mode()
           << "\n publicKeyAlgorithm: " << protect(sig.publicKeyAlgorithmAsString())
           << "\n hashAlgorithm:      " << protect(sig.hashAlgorithmAsString())
           << "\n signatureClass:     " << sig.signatureClass()
           << '\n';
    }
    return os << ')';
}

std::ostream &GpgME::operator<<(std::ostream &os, const InvalidSigningKey &key)
{
    os << "GpgME::InvalidSigningKey(";
    if (!key.isNull()) {
        os << "\n fingerprint: " << protect(key.fingerprint())
           << "\n reason:      " << key.reason()
           << '\n';
    }
    return os << ')';
}
