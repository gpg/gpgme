/*
    qgpgmekeylistjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004,2008 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH

    QGpgME is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.

    QGpgME is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    In addition, as a special exception, the copyright holders give
    permission to link the code of this program with any edition of
    the Qt library by Trolltech AS, Norway (or with modified versions
    of Qt that use the same license as Qt), and distribute linked
    combinations including the two.  You must obey the GNU General
    Public License in all respects for all of the code used other than
    Qt.  If you modify this file, you may extend this exception to
    your version of the file, but you are not obligated to do so.  If
    you do not wish to do so, delete this exception statement from
    your version.
*/

#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include "qgpgmekeylistjob.h"

#include <gpgme++/key.h>
#include <gpgme++/context.h>
#include <gpgme++/keylistresult.h>
#include <gpg-error.h>

#include <QStringList>

#include <algorithm>

#include <cstdlib>
#include <cstring>
#include <cassert>

using namespace QGpgME;
using namespace GpgME;

QGpgMEKeyListJob::QGpgMEKeyListJob(Context *context)
    : mixin_type(context)
    , mSecretOnly(false)
{
    lateInitialization();
}

QGpgMEKeyListJob::~QGpgMEKeyListJob() {}

static KeyListResult do_list_keys(Context *ctx, const QStringList &pats, std::vector<Key> &keys, bool secretOnly)
{

    const _detail::PatternConverter pc(pats);

    if (const Error err = ctx->startKeyListing(pc.patterns(), secretOnly)) {
        return KeyListResult(nullptr, err);
    }

    Error err;
    do {
        keys.push_back(ctx->nextKey(err));
    } while (!err);

    keys.pop_back();

    const KeyListResult result = ctx->endKeyListing();
    ctx->cancelPendingOperation();
    return result;
}

static QGpgMEKeyListJob::result_type list_keys(Context *ctx, QStringList pats, bool secretOnly)
{
    if (pats.size() < 2) {
        std::vector<Key> keys;
        const KeyListResult r = do_list_keys(ctx, pats, keys, secretOnly);
        return std::make_tuple(r, keys, QString(), Error());
    }

    // The communication channel between gpgme and gpgsm is limited in
    // the number of patterns that can be transported, but they won't
    // say to how much, so we need to find out ourselves if we get a
    // LINE_TOO_LONG error back...

    // We could of course just feed them single patterns, and that would
    // probably be easier, but the performance penalty would currently
    // be noticeable.

    unsigned int chunkSize = pats.size();
retry:
    std::vector<Key> keys;
    keys.reserve(pats.size());
    KeyListResult result;
    do {
        const KeyListResult this_result = do_list_keys(ctx, pats.mid(0, chunkSize), keys, secretOnly);
        if (this_result.error().code() == GPG_ERR_LINE_TOO_LONG) {
            // got LINE_TOO_LONG, try a smaller chunksize:
            chunkSize /= 2;
            if (chunkSize < 1)
                // chunks smaller than one can't be -> return the error.
            {
                return std::make_tuple(this_result, keys, QString(), Error());
            } else {
                goto retry;
            }
        } else if (this_result.error().code() == GPG_ERR_EOF) {
            // early end of keylisting (can happen when ~/.gnupg doesn't
            // exist). Fakeing an empty result:
            return std::make_tuple(KeyListResult(), std::vector<Key>(), QString(), Error());
        }
        // ok, that seemed to work...
        result.mergeWith(this_result);
        if (result.error().code()) {
            break;
        }
        pats = pats.mid(chunkSize);
    } while (!pats.empty());
    return std::make_tuple(result, keys, QString(), Error());
}

Error QGpgMEKeyListJob::start(const QStringList &patterns, bool secretOnly)
{
    mSecretOnly = secretOnly;
    run(std::bind(&list_keys, std::placeholders::_1, patterns, secretOnly));
    return Error();
}

KeyListResult QGpgMEKeyListJob::exec(const QStringList &patterns, bool secretOnly, std::vector<Key> &keys)
{
    mSecretOnly = secretOnly;
    const result_type r = list_keys(context(), patterns, secretOnly);
    resultHook(r);
    keys = std::get<1>(r);
    return std::get<0>(r);
}

void QGpgMEKeyListJob::resultHook(const result_type &tuple)
{
    for (const Key &key : std::get<1>(tuple)) {
        Q_EMIT nextKey(key);
    }
}

void QGpgMEKeyListJob::addMode(KeyListMode mode)
{
    context()->addKeyListMode(mode);
}

#include "qgpgmekeylistjob.moc"
