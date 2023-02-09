/*
  verificationresult.cpp - wraps a gpgme verify result
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

#include <verificationresult.h>
#include <notation.h>
#include "result_p.h"
#include "util.h"
#include "key.h"
#include "context.h"

#include <gpgme.h>

#include <istream>
#include <algorithm>
#include <iterator>
#include <string>
#include <cstring>
#include <cstdlib>

#include <string.h>

class GpgME::VerificationResult::Private
{
public:
    explicit Private(const gpgme_verify_result_t r)
    {
        if (!r) {
            return;
        }
        if (r->file_name) {
            file_name = r->file_name;
        }
        // copy recursively, using compiler-generated copy ctor.
        // We just need to handle the pointers in the structs:
        for (gpgme_signature_t is = r->signatures ; is ; is = is->next) {
            gpgme_signature_t scopy = new _gpgme_signature(*is);
            if (is->fpr) {
                scopy->fpr = strdup(is->fpr);
            }
// PENDING(marc) why does this crash on Windows in strdup()?
# ifndef _WIN32
            if (is->pka_address) {
                scopy->pka_address = strdup(is->pka_address);
            }
# else
            scopy->pka_address = nullptr;
# endif
            scopy->next = nullptr;
            sigs.push_back(scopy);
            // copy keys
            if (scopy->key) {
                keys.push_back(Key(scopy->key, true));
            } else {
                keys.push_back(Key());
            }
            // copy notations:
            nota.push_back(std::vector<Nota>());
            purls.push_back(nullptr);
            for (gpgme_sig_notation_t in = is->notations ; in ; in = in->next) {
                if (!in->name) {
                    if (in->value) {
                        purls.back() = strdup(in->value);   // policy url
                    }
                    continue;
                }
                Nota n = { nullptr, nullptr, in->flags };
                n.name = strdup(in->name);
                if (in->value) {
                    n.value = strdup(in->value);
                }
                nota.back().push_back(n);
            }
        }
    }
    ~Private()
    {
        for (std::vector<gpgme_signature_t>::iterator it = sigs.begin() ; it != sigs.end() ; ++it) {
            std::free((*it)->fpr);
            std::free((*it)->pka_address);
            delete *it; *it = nullptr;
        }
        for (std::vector< std::vector<Nota> >::iterator it = nota.begin() ; it != nota.end() ; ++it) {
            for (std::vector<Nota>::iterator jt = it->begin() ; jt != it->end() ; ++jt) {
                std::free(jt->name);  jt->name = nullptr;
                std::free(jt->value); jt->value = nullptr;
            }
        }
        std::for_each(purls.begin(), purls.end(), &std::free);
    }

    struct Nota {
        char *name;
        char *value;
        gpgme_sig_notation_flags_t flags;
    };

    std::vector<gpgme_signature_t> sigs;
    std::vector< std::vector<Nota> > nota;
    std::vector<GpgME::Key> keys;
    std::vector<char *> purls;
    std::string file_name;
    Protocol proto;
};

GpgME::VerificationResult::VerificationResult(gpgme_ctx_t ctx, int error)
    : GpgME::Result(error), d()
{
    init(ctx);
}

GpgME::VerificationResult::VerificationResult(gpgme_ctx_t ctx, const Error &error)
    : GpgME::Result(error), d()
{
    init(ctx);
}

void GpgME::VerificationResult::init(gpgme_ctx_t ctx)
{
    if (!ctx) {
        return;
    }
    gpgme_verify_result_t res = gpgme_op_verify_result(ctx);
    if (!res) {
        return;
    }
    d.reset(new Private(res));
    gpgme_protocol_t proto = gpgme_get_protocol(ctx);
    d->proto = proto == GPGME_PROTOCOL_OpenPGP ? OpenPGP :
               proto == GPGME_PROTOCOL_CMS ? CMS :
               UnknownProtocol;
}

make_standard_stuff(VerificationResult)

const char *GpgME::VerificationResult::fileName() const
{
    return d ? d->file_name.c_str() : nullptr ;
}

unsigned int GpgME::VerificationResult::numSignatures() const
{
    return d ? d->sigs.size() : 0 ;
}

GpgME::Signature GpgME::VerificationResult::signature(unsigned int idx) const
{
    return Signature(d, idx);
}

std::vector<GpgME::Signature> GpgME::VerificationResult::signatures() const
{
    if (!d) {
        return std::vector<Signature>();
    }
    std::vector<Signature> result;
    result.reserve(d->sigs.size());
    for (unsigned int i = 0 ; i < d->sigs.size() ; ++i) {
        result.push_back(Signature(d, i));
    }
    return result;
}

GpgME::Signature::Signature(const std::shared_ptr<VerificationResult::Private> &parent, unsigned int i)
    : d(parent), idx(i)
{
}

GpgME::Signature::Signature() : d(), idx(0) {}

bool GpgME::Signature::isNull() const
{
    return !d || idx >= d->sigs.size() ;
}

GpgME::Signature::Summary GpgME::Signature::summary() const
{
    if (isNull()) {
        return None;
    }
    gpgme_sigsum_t sigsum = d->sigs[idx]->summary;
    unsigned int result = 0;
    if (sigsum & GPGME_SIGSUM_VALID) {
        result |= Valid;
    }
    if (sigsum & GPGME_SIGSUM_GREEN) {
        result |= Green;
    }
    if (sigsum & GPGME_SIGSUM_RED) {
        result |= Red;
    }
    if (sigsum & GPGME_SIGSUM_KEY_REVOKED) {
        result |= KeyRevoked;
    }
    if (sigsum & GPGME_SIGSUM_KEY_EXPIRED) {
        result |= KeyExpired;
    }
    if (sigsum & GPGME_SIGSUM_SIG_EXPIRED) {
        result |= SigExpired;
    }
    if (sigsum & GPGME_SIGSUM_KEY_MISSING) {
        result |= KeyMissing;
    }
    if (sigsum & GPGME_SIGSUM_CRL_MISSING) {
        result |= CrlMissing;
    }
    if (sigsum & GPGME_SIGSUM_CRL_TOO_OLD) {
        result |= CrlTooOld;
    }
    if (sigsum & GPGME_SIGSUM_BAD_POLICY) {
        result |= BadPolicy;
    }
    if (sigsum & GPGME_SIGSUM_SYS_ERROR) {
        result |= SysError;
    }
    if (sigsum & GPGME_SIGSUM_TOFU_CONFLICT) {
        result |= TofuConflict;
    }
    return static_cast<Summary>(result);
}

const char *GpgME::Signature::fingerprint() const
{
    return isNull() ? nullptr : d->sigs[idx]->fpr ;
}

GpgME::Error GpgME::Signature::status() const
{
    return Error(isNull() ? 0 : d->sigs[idx]->status);
}

time_t GpgME::Signature::creationTime() const
{
    return static_cast<time_t>(isNull() ? 0 : d->sigs[idx]->timestamp);
}

time_t GpgME::Signature::expirationTime() const
{
    return static_cast<time_t>(isNull() ? 0 : d->sigs[idx]->exp_timestamp);
}

bool GpgME::Signature::neverExpires() const
{
    return expirationTime() == (time_t)0;
}

bool GpgME::Signature::isWrongKeyUsage() const
{
    return !isNull() && d->sigs[idx]->wrong_key_usage;
}

bool GpgME::Signature::isVerifiedUsingChainModel() const
{
    return !isNull() && d->sigs[idx]->chain_model;
}

bool GpgME::Signature::isDeVs() const
{
    return !isNull() && d->sigs[idx]->is_de_vs;
}

GpgME::Signature::PKAStatus GpgME::Signature::pkaStatus() const
{
    if (!isNull()) {
        return static_cast<PKAStatus>(d->sigs[idx]->pka_trust);
    }
    return UnknownPKAStatus;
}

const char *GpgME::Signature::pkaAddress() const
{
    if (!isNull()) {
        return d->sigs[idx]->pka_address;
    }
    return nullptr;
}

GpgME::Signature::Validity GpgME::Signature::validity() const
{
    if (isNull()) {
        return Unknown;
    }
    switch (d->sigs[idx]->validity) {
    default:
    case GPGME_VALIDITY_UNKNOWN:   return Unknown;
    case GPGME_VALIDITY_UNDEFINED: return Undefined;
    case GPGME_VALIDITY_NEVER:     return Never;
    case GPGME_VALIDITY_MARGINAL:  return Marginal;
    case GPGME_VALIDITY_FULL:      return Full;
    case GPGME_VALIDITY_ULTIMATE:  return Ultimate;
    }
}

char GpgME::Signature::validityAsString() const
{
    if (isNull()) {
        return '?';
    }
    switch (d->sigs[idx]->validity) {
    default:
    case GPGME_VALIDITY_UNKNOWN:   return '?';
    case GPGME_VALIDITY_UNDEFINED: return 'q';
    case GPGME_VALIDITY_NEVER:     return 'n';
    case GPGME_VALIDITY_MARGINAL:  return 'm';
    case GPGME_VALIDITY_FULL:      return 'f';
    case GPGME_VALIDITY_ULTIMATE:  return 'u';
    }
}

GpgME::Error GpgME::Signature::nonValidityReason() const
{
    return Error(isNull() ? 0 : d->sigs[idx]->validity_reason);
}

unsigned int GpgME::Signature::publicKeyAlgorithm() const
{
    if (!isNull()) {
        return d->sigs[idx]->pubkey_algo;
    }
    return 0;
}

const char *GpgME::Signature::publicKeyAlgorithmAsString() const
{
    if (!isNull()) {
        return gpgme_pubkey_algo_name(d->sigs[idx]->pubkey_algo);
    }
    return nullptr;
}

unsigned int GpgME::Signature::hashAlgorithm() const
{
    if (!isNull()) {
        return d->sigs[idx]->hash_algo;
    }
    return 0;
}

const char *GpgME::Signature::hashAlgorithmAsString() const
{
    if (!isNull()) {
        return gpgme_hash_algo_name(d->sigs[idx]->hash_algo);
    }
    return nullptr;
}

const char *GpgME::Signature::policyURL() const
{
    return isNull() ? nullptr : d->purls[idx] ;
}

GpgME::Notation GpgME::Signature::notation(unsigned int nidx) const
{
    return GpgME::Notation(d, idx, nidx);
}

std::vector<GpgME::Notation> GpgME::Signature::notations() const
{
    if (isNull()) {
        return std::vector<GpgME::Notation>();
    }
    std::vector<GpgME::Notation> result;
    result.reserve(d->nota[idx].size());
    for (unsigned int i = 0 ; i < d->nota[idx].size() ; ++i) {
        result.push_back(GpgME::Notation(d, idx, i));
    }
    return result;
}

GpgME::Key GpgME::Signature::key() const
{
    if (isNull()) {
        return Key();
    }
    return d->keys[idx];
}

GpgME::Key GpgME::Signature::key(bool search, bool update) const
{
    if (isNull()) {
        return Key();
    }

    GpgME::Key ret = key();
    if (ret.isNull() && search && fingerprint ()) {
        auto ctx = Context::createForProtocol (d->proto);
        if (ctx) {
            ctx->setKeyListMode(KeyListMode::Local |
                        KeyListMode::Signatures |
                        KeyListMode::SignatureNotations |
                        KeyListMode::Validate |
                        KeyListMode::WithTofu |
                        KeyListMode::WithKeygrip);
            Error e;
            ret = d->keys[idx] = ctx->key(fingerprint(), e, false);
            delete ctx;
        }
    }
    if (update) {
        d->keys[idx].update();
        ret = d->keys[idx];
    }
    return ret;
}

class GpgME::Notation::Private
{
public:
    Private() : d(), sidx(0), nidx(0), nota(nullptr) {}
    Private(const std::shared_ptr<VerificationResult::Private> &priv, unsigned int sindex, unsigned int nindex)
        : d(priv), sidx(sindex), nidx(nindex), nota(nullptr)
    {

    }
    Private(gpgme_sig_notation_t n)
        : d(), sidx(0), nidx(0), nota(n ? new _gpgme_sig_notation(*n) : nullptr)
    {
        if (nota && nota->name) {
            nota->name = strdup(nota->name);
        }
        if (nota && nota->value) {
            nota->value = strdup(nota->value);
        }
    }
    Private(const Private &other)
        : d(other.d), sidx(other.sidx), nidx(other.nidx), nota(other.nota)
    {
        if (nota) {
            nota->name = strdup(nota->name);
            nota->value = strdup(nota->value);
        }
    }
    ~Private()
    {
        if (nota) {
            std::free(nota->name);  nota->name = nullptr;
            std::free(nota->value); nota->value = nullptr;
            delete nota;
        }
    }

    std::shared_ptr<VerificationResult::Private> d;
    unsigned int sidx, nidx;
    gpgme_sig_notation_t nota;
};

GpgME::Notation::Notation(const std::shared_ptr<VerificationResult::Private> &parent, unsigned int sindex, unsigned int nindex)
    : d(new Private(parent, sindex, nindex))
{

}

GpgME::Notation::Notation(gpgme_sig_notation_t nota)
    : d(new Private(nota))
{

}

GpgME::Notation::Notation() : d() {}

bool GpgME::Notation::isNull() const
{
    if (!d) {
        return true;
    }
    if (d->d) {
        return d->sidx >= d->d->nota.size() || d->nidx >= d->d->nota[d->sidx].size() ;
    }
    return !d->nota;
}

const char *GpgME::Notation::name() const
{
    return
        isNull() ? nullptr :
        d->d ? d->d->nota[d->sidx][d->nidx].name :
        d->nota ? d->nota->name : nullptr ;
}

const char *GpgME::Notation::value() const
{
    return
        isNull() ? nullptr :
        d->d ? d->d->nota[d->sidx][d->nidx].value :
        d->nota ? d->nota->value : nullptr ;
}

GpgME::Notation::Flags GpgME::Notation::flags() const
{
    return
        convert_from_gpgme_sig_notation_flags_t(
            isNull() ? 0:
            d->d ? d->d->nota[d->sidx][d->nidx].flags :
            d->nota ? d->nota->flags : 0);
}

bool GpgME::Notation::isHumanReadable() const
{
    return flags() & HumanReadable;
}

bool GpgME::Notation::isCritical() const
{
    return flags() & Critical;
}

std::ostream &GpgME::operator<<(std::ostream &os, const VerificationResult &result)
{
    os << "GpgME::VerificationResult(";
    if (!result.isNull()) {
        os << "\n error:      " << result.error()
           << "\n fileName:   " << protect(result.fileName())
           << "\n signatures:\n";
        const std::vector<Signature> sigs = result.signatures();
        std::copy(sigs.begin(), sigs.end(),
                  std::ostream_iterator<Signature>(os, "\n"));
    }
    return os << ')';
}

std::ostream &GpgME::operator<<(std::ostream &os, Signature::PKAStatus pkaStatus)
{
    os << "GpgME::Signature::PKAStatus(";
    switch (pkaStatus) {
#define OUTPUT( x ) case GpgME::Signature:: x: os << #x; break
        OUTPUT(UnknownPKAStatus);
        OUTPUT(PKAVerificationFailed);
        OUTPUT(PKAVerificationSucceeded);
#undef OUTPUT
    default:
        os << "??? (" << static_cast<int>(pkaStatus) << ')';
        break;
    }
    return os << ')';
}

std::ostream &GpgME::operator<<(std::ostream &os, Signature::Summary summary)
{
    os << "GpgME::Signature::Summary(";
    if (summary == Signature::None) {
        os << "None";
    } else {
#define OUTPUT( x ) if ( !(summary & (GpgME::Signature:: x)) ) {} else do { os << #x " "; } while(0)
        OUTPUT(Valid);
        OUTPUT(Green);
        OUTPUT(Red);
        OUTPUT(KeyRevoked);
        OUTPUT(KeyExpired);
        OUTPUT(SigExpired);
        OUTPUT(KeyMissing);
        OUTPUT(CrlMissing);
        OUTPUT(CrlTooOld);
        OUTPUT(BadPolicy);
        OUTPUT(SysError);
        OUTPUT(TofuConflict);
#undef OUTPUT
    }
    return os << ')';
}

std::ostream &GpgME::operator<<(std::ostream &os, const Signature &sig)
{
    os << "GpgME::Signature(";
    if (!sig.isNull()) {
        os << "\n Summary:                   " << sig.summary()
           << "\n Fingerprint:               " << protect(sig.fingerprint())
           << "\n Status:                    " << sig.status()
           << "\n creationTime:              " << sig.creationTime()
           << "\n expirationTime:            " << sig.expirationTime()
           << "\n isWrongKeyUsage:           " << sig.isWrongKeyUsage()
           << "\n isVerifiedUsingChainModel: " << sig.isVerifiedUsingChainModel()
           << "\n pkaStatus:                 " << sig.pkaStatus()
           << "\n pkaAddress:                " << protect(sig.pkaAddress())
           << "\n validity:                  " << sig.validityAsString()
           << "\n nonValidityReason:         " << sig.nonValidityReason()
           << "\n publicKeyAlgorithm:        " << protect(sig.publicKeyAlgorithmAsString())
           << "\n hashAlgorithm:             " << protect(sig.hashAlgorithmAsString())
           << "\n policyURL:                 " << protect(sig.policyURL())
           << "\n isDeVs                     " << sig.isDeVs()
           << "\n notations:\n";
        const std::vector<Notation> nota = sig.notations();
        std::copy(nota.begin(), nota.end(),
                  std::ostream_iterator<Notation>(os, "\n"));
    }
    return os << ')';
}

std::ostream &GpgME::operator<<(std::ostream &os, Notation::Flags flags)
{
    os << "GpgME::Notation::Flags(";
    if (flags == Notation::NoFlags) {
        os << "NoFlags";
    } else {
#define OUTPUT( x ) if ( !(flags & (GpgME::Notation:: x)) ) {} else do { os << #x " "; } while(0)
        OUTPUT(HumanReadable);
        OUTPUT(Critical);
#undef OUTPUT
    }
    return os << ')';
}

std::ostream &GpgME::operator<<(std::ostream &os, const Notation &nota)
{
    os << "GpgME::Signature::Notation(";
    if (!nota.isNull()) {
        os << "\n name:  " << protect(nota.name())
           << "\n value: " << protect(nota.value())
           << "\n flags: " << nota.flags()
           << '\n';
    }
    return os << ")";
}
