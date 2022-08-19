/*
  importresult.cpp - wraps a gpgme import result
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

#include <importresult.h>
#include "result_p.h"

#include <gpgme.h>
#include <cstdlib>
#include <cstring>

#include <string.h>
#include <strings.h>
#include <istream>
#include <iterator>

class GpgME::ImportResult::Private
{
public:
    Private(const _gpgme_op_import_result &r) : res(r)
    {
        // copy recursively, using compiler-generated copy ctor.
        // We just need to handle the pointers in the structs:
        for (gpgme_import_status_t is = r.imports ; is ; is = is->next) {
            gpgme_import_status_t copy = new _gpgme_import_status(*is);
            if (is->fpr) {
                copy->fpr = strdup(is->fpr);
            }
            copy->next = nullptr;
            imports.push_back(copy);
        }
        res.imports = nullptr;
    }
    ~Private()
    {
        for (std::vector<gpgme_import_status_t>::iterator it = imports.begin() ; it != imports.end() ; ++it) {
            std::free((*it)->fpr);
            delete *it; *it = nullptr;
        }
    }

    _gpgme_op_import_result res;
    std::vector<gpgme_import_status_t> imports;
};

GpgME::ImportResult::ImportResult(gpgme_ctx_t ctx, int error)
    : GpgME::Result(error), d()
{
    init(ctx);
}

GpgME::ImportResult::ImportResult(gpgme_ctx_t ctx, const Error &error)
    : GpgME::Result(error), d()
{
    init(ctx);
}

void GpgME::ImportResult::init(gpgme_ctx_t ctx)
{
    if (!ctx) {
        return;
    }
    gpgme_import_result_t res = gpgme_op_import_result(ctx);
    if (!res) {
        return;
    }
    d.reset(new Private(*res));
}

make_standard_stuff(ImportResult)

void GpgME::ImportResult::mergeWith(const ImportResult &other)
{
    if (other.isNull()) {
        return;
    }
    if (isNull()) {   // just assign
        operator=(other);
        return;
    }

    // Add the numbers of considered keys; the number will be corrected when
    // merging the imports to account for duplicates
    d->res.considered += other.d->res.considered;
    // Add the numbers of keys without user ID; may count duplicates
    d->res.no_user_id += other.d->res.no_user_id;
    // Add the numbers of imported keys
    d->res.imported += other.d->res.imported;
    // Add the numbers of imported RSA keys
    d->res.imported_rsa += other.d->res.imported_rsa;
    // Add the numbers of unchanged keys; the number will be corrected when
    // merging the imports to account for keys changed by this import
    d->res.unchanged += other.d->res.unchanged;
    // Add the numbers of new user IDs
    d->res.new_user_ids += other.d->res.new_user_ids;
    // Add the numbers of new subkeys
    d->res.new_sub_keys += other.d->res.new_sub_keys;
    // Add the numbers of new signatures
    d->res.new_signatures += other.d->res.new_signatures;
    // Add the numbers of new revocations
    d->res.new_revocations += other.d->res.new_revocations;

    // Add the numbers of considered secret keys; the number will be corrected when
    // merging the imports to account for duplicates
    d->res.secret_read += other.d->res.secret_read;
    // Add the numbers of imported secret keys
    d->res.secret_imported += other.d->res.secret_imported;
    // Add the numbers of unchanged secret keys; the number will be corrected when
    // merging the imports to account for keys changed by this import
    d->res.secret_unchanged += other.d->res.secret_unchanged;

    // Add the numbers of new keys that were skipped; may count duplicates
    d->res.skipped_new_keys += other.d->res.skipped_new_keys;
    // Add the numbers of keys that were not imported; may count duplicates
    d->res.not_imported += other.d->res.not_imported;
    // Add the numbers of v3 keys that were skipped; may count duplicates
    d->res.skipped_v3_keys += other.d->res.skipped_v3_keys;

    // Look at the list of keys for which an import was attempted during the
    // other import to correct some of the consolidated numbers
    for (auto it = std::begin(other.d->imports), end = std::end(other.d->imports); it != end; ++it) {
        const char *fpr = (*it)->fpr;
        if (!fpr || !*fpr) {
            // we cannot derive any useful information about an import if the
            // fingerprint is null or empty
            continue;
        }
        // was this key also considered during the first import
        const auto consideredInFirstImports =
            std::any_of(std::begin(d->imports), std::end(d->imports), [fpr](const gpgme_import_status_t i) {
                return i->fpr && !strcmp(i->fpr, fpr);
            });
        // did we see this key already in the list of keys of the other import
        const auto consideredInPreviousOtherImports =
            std::any_of(std::begin(other.d->imports), it, [fpr](const gpgme_import_status_t i) {
                return i->fpr && !strcmp(i->fpr, fpr);
            });
        // was anything added to this key during the other import
        const auto changedInOtherImports =
            std::any_of(std::begin(other.d->imports), std::end(other.d->imports), [fpr](const gpgme_import_status_t i) {
                return i->fpr && !strcmp(i->fpr, fpr) && (i->status != 0);
            });
        if (consideredInFirstImports && !consideredInPreviousOtherImports) {
            // key was also considered during first import, but not before in the list of other imports
            d->res.considered -= 1;
            if (!changedInOtherImports) {
                // key was (most likely) counted as unchanged in the second import;
                // this needs to be corrected (regardless of whether it was changed in the first import)
                d->res.unchanged -= 1;
            }
        }

        // now do the same for the secret key counts
        const auto secretKeyConsideredInFirstImports =
            std::any_of(std::begin(d->imports), std::end(d->imports), [fpr](const gpgme_import_status_t i) {
                return i->fpr && !strcmp(i->fpr, fpr) && (i->status & GPGME_IMPORT_SECRET);
            });
        const auto secretKeyConsideredInPreviousOtherImports =
            std::any_of(std::begin(other.d->imports), it, [fpr](const gpgme_import_status_t i) {
                return i->fpr && !strcmp(i->fpr, fpr) && (i->status & GPGME_IMPORT_SECRET);
            });
        const auto secretKeyChangedInOtherImports =
            std::any_of(std::begin(other.d->imports), std::end(other.d->imports), [fpr](const gpgme_import_status_t i) {
                return i->fpr && !strcmp(i->fpr, fpr) && (i->status & GPGME_IMPORT_SECRET) && (i->status != GPGME_IMPORT_SECRET);
            });
        if (secretKeyConsideredInFirstImports && !secretKeyConsideredInPreviousOtherImports) {
            // key was also considered during first import, but not before in the list of other imports
            d->res.secret_read -= 1;
            if (!secretKeyChangedInOtherImports) {
                // key was (most likely) counted as unchanged in the second import;
                // this needs to be corrected (regardless of whether it was changed in the first import)
                d->res.secret_unchanged -= 1;
            }
        }
    }

    // Now append the list of keys for which an import was attempted during the
    // other import
    d->imports.reserve(d->imports.size() + other.d->imports.size());
    std::transform(std::begin(other.d->imports), std::end(other.d->imports),
                   std::back_inserter(d->imports),
                   [](const gpgme_import_status_t import) {
                       gpgme_import_status_t copy = new _gpgme_import_status{*import};
                       if (import->fpr) {
                           copy->fpr = strdup(import->fpr);
                       }
                       copy->next = nullptr; // should already be null, but better safe than sorry
                       return copy;
                   });

    // Finally, merge the error if there was none yet
    if (!bool(error())) {
        Result::operator=(other);
    }
}

int GpgME::ImportResult::numConsidered() const
{
    return d ? d->res.considered : 0 ;
}

int GpgME::ImportResult::numKeysWithoutUserID() const
{
    return d ? d->res.no_user_id : 0 ;
}

int GpgME::ImportResult::numImported() const
{
    return d ? d->res.imported : 0 ;
}

int GpgME::ImportResult::numRSAImported() const
{
    return d ? d->res.imported_rsa : 0 ;
}

int GpgME::ImportResult::numUnchanged() const
{
    return d ? d->res.unchanged : 0 ;
}

int GpgME::ImportResult::newUserIDs() const
{
    return d ? d->res.new_user_ids : 0 ;
}

int GpgME::ImportResult::newSubkeys() const
{
    return d ? d->res.new_sub_keys : 0 ;
}

int GpgME::ImportResult::newSignatures() const
{
    return d ? d->res.new_signatures : 0 ;
}

int GpgME::ImportResult::newRevocations() const
{
    return d ? d->res.new_revocations : 0 ;
}

int GpgME::ImportResult::numSecretKeysConsidered() const
{
    return d ? d->res.secret_read : 0 ;
}

int GpgME::ImportResult::numSecretKeysImported() const
{
    return d ? d->res.secret_imported : 0 ;
}

int GpgME::ImportResult::numSecretKeysUnchanged() const
{
    return d ? d->res.secret_unchanged : 0 ;
}

int GpgME::ImportResult::notImported() const
{
    return d ? d->res.not_imported : 0 ;
}

int GpgME::ImportResult::numV3KeysSkipped() const
{
    return d ? d->res.skipped_v3_keys : 0 ;
}

GpgME::Import GpgME::ImportResult::import(unsigned int idx) const
{
    return Import(d, idx);
}

std::vector<GpgME::Import> GpgME::ImportResult::imports() const
{
    if (!d) {
        return std::vector<Import>();
    }
    std::vector<Import> result;
    result.reserve(d->imports.size());
    for (unsigned int i = 0 ; i < d->imports.size() ; ++i) {
        result.push_back(Import(d, i));
    }
    return result;
}

GpgME::Import::Import(const std::shared_ptr<ImportResult::Private> &parent, unsigned int i)
    : d(parent), idx(i)
{

}

GpgME::Import::Import() : d(), idx(0) {}

bool GpgME::Import::isNull() const
{
    return !d || idx >= d->imports.size() ;
}

const char *GpgME::Import::fingerprint() const
{
    return isNull() ? nullptr : d->imports[idx]->fpr ;
}

GpgME::Error GpgME::Import::error() const
{
    return Error(isNull() ? 0 : d->imports[idx]->result);
}

GpgME::Import::Status GpgME::Import::status() const
{
    if (isNull()) {
        return Unknown;
    }
    const unsigned int s = d->imports[idx]->status;
    unsigned int result = Unknown;
    if (s & GPGME_IMPORT_NEW) {
        result |= NewKey;
    }
    if (s & GPGME_IMPORT_UID) {
        result |= NewUserIDs;
    }
    if (s & GPGME_IMPORT_SIG) {
        result |= NewSignatures;
    }
    if (s & GPGME_IMPORT_SUBKEY) {
        result |= NewSubkeys;
    }
    if (s & GPGME_IMPORT_SECRET) {
        result |= ContainedSecretKey;
    }
    return static_cast<Status>(result);
}

std::ostream &GpgME::operator<<(std::ostream &os,
                                const GpgME::ImportResult &result)
{
    os << "GpgME::ImportResult(";
    if (!result.isNull()) {
        os << "\n considered:          " << result.numConsidered()
           << "\n without UID:         " << result.numKeysWithoutUserID()
           << "\n imported:            " << result.numImported()
           << "\n RSA Imported:        " << result.numRSAImported()
           << "\n unchanged:           " << result.numUnchanged()
           << "\n newUserIDs:          " << result.newUserIDs()
           << "\n newSubkeys:          " << result.newSubkeys()
           << "\n newSignatures:       " << result.newSignatures()
           << "\n newRevocations:      " << result.newRevocations()
           << "\n numSecretKeysConsidered: " << result.numSecretKeysConsidered()
           << "\n numSecretKeysImported:   " << result.numSecretKeysImported()
           << "\n numSecretKeysUnchanged:  " << result.numSecretKeysUnchanged()
           << "\n"
           << "\n notImported:         " << result.notImported()
           << "\n numV3KeysSkipped:    " << result.numV3KeysSkipped()
           << "\n imports:\n";
        const std::vector<Import> imp = result.imports();
        std::copy(imp.begin(), imp.end(),
                  std::ostream_iterator<Import>(os, "\n"));
    }
    return os << ')';
}

std::ostream &GpgME::operator<<(std::ostream &os, const GpgME::Import &imp)
{
    os << "GpgME::Import(";
    if (!imp.isNull()) {
        os << "\n fpr:       " << (imp.fingerprint() ? imp.fingerprint() : "null")
           << "\n status:    " << imp.status()
           << "\n err:       " << imp.error();
    }
    return os << ')';
}
