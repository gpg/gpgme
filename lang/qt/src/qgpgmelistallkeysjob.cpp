/*
    qgpgmelistallkeysjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004,2008 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH
    Copyright (c) 2022,2023 g10 Code GmbH
    Software engineering by Ingo Klöcker <dev@ingo-kloecker.de>

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

#include "qgpgmelistallkeysjob.h"

#include "listallkeysjob_p.h"

#include "debug.h"
#include "key.h"
#include "context.h"
#include "engineinfo.h"
#include "global.h"
#include "keylistresult.h"
#include "qgpgme_debug.h"

#include <gpg-error.h>

#include <algorithm>

#include <cstdlib>
#include <cstring>
#include <cassert>

using namespace QGpgME;
using namespace GpgME;

namespace
{

class QGpgMEListAllKeysJobPrivate : public ListAllKeysJobPrivate
{
    QGpgMEListAllKeysJob *q = nullptr;

public:
    QGpgMEListAllKeysJobPrivate(QGpgMEListAllKeysJob *qq)
        : q{qq}
    {
    }

    ~QGpgMEListAllKeysJobPrivate() override = default;

private:
    void startNow() override
    {
        q->run();
    }
};

}

QGpgMEListAllKeysJob::QGpgMEListAllKeysJob(Context *context)
    : mixin_type(context),
      mResult()
{
    setJobPrivate(this, std::unique_ptr<QGpgMEListAllKeysJobPrivate>{new QGpgMEListAllKeysJobPrivate{this}});
    lateInitialization();
}

QGpgMEListAllKeysJob::~QGpgMEListAllKeysJob() {}

namespace {

static KeyListResult do_list_keys_legacy(Context *ctx, std::vector<Key> &keys, bool secretOnly)
{

    const char **pat = nullptr;
    if (const Error err = ctx->startKeyListing(pat, secretOnly)) {
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

template <typename ForwardIterator, typename BinaryPredicate>
ForwardIterator unique_by_merge(ForwardIterator first, ForwardIterator last, BinaryPredicate pred)
{
    first = std::adjacent_find(first, last, pred);
    if (first == last) {
        return last;
    }

    ForwardIterator dest = first;
    dest->mergeWith(*++first);
    while (++first != last)
        if (pred(*dest, *first)) {
            dest->mergeWith(*first);
        } else {
            *++dest = *first;
        }
    return ++dest;
}

static void merge_keys(std::vector<Key> &merged, std::vector<Key> &pub, std::vector<Key> &sec)
{
    merged.reserve(pub.size() + sec.size());

    std::merge(pub.begin(), pub.end(),
               sec.begin(), sec.end(),
               std::back_inserter(merged),
               ByFingerprint<std::less>());

    merged.erase(unique_by_merge(merged.begin(), merged.end(), ByFingerprint<std::equal_to>()),
                 merged.end());
}

static QGpgMEListAllKeysJob::result_type list_keys_legacy(Context *ctx, bool mergeKeys)
{
    std::vector<Key> pub, sec, merged;
    KeyListResult r;

    r.mergeWith(do_list_keys_legacy(ctx, pub, false));
    std::sort(pub.begin(), pub.end(), ByFingerprint<std::less>());

    r.mergeWith(do_list_keys_legacy(ctx, sec, true));
    std::sort(sec.begin(), sec.end(), ByFingerprint<std::less>());

    if (mergeKeys) {
        merge_keys(merged, pub, sec);
    } else {
        merged.swap(pub);
    }
    return std::make_tuple(r, merged, sec, QString(), Error());
}

static KeyListResult do_list_keys(Context *ctx, std::vector<Key> &keys)
{
    const unsigned int keyListMode = ctx->keyListMode();
    ctx->addKeyListMode(KeyListMode::WithSecret);

    const char **pat = nullptr;
    if (const Error err = ctx->startKeyListing(pat)) {
        ctx->setKeyListMode(keyListMode);
        return KeyListResult(nullptr, err);
    }

    Error err;
    do {
        keys.push_back(ctx->nextKey(err));
    } while (!err);

    keys.pop_back();

    const KeyListResult result = ctx->endKeyListing();
    ctx->setKeyListMode(keyListMode);

    ctx->cancelPendingOperation();
    return result;
}

static QGpgMEListAllKeysJob::result_type list_keys(Context *ctx, bool mergeKeys, ListAllKeysJob::Options options)
{
    if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.1.0") {
        return list_keys_legacy(ctx, mergeKeys);
    }

    if (options & ListAllKeysJob::DisableAutomaticTrustDatabaseCheck) {
        auto err = ctx->setFlag("no-auto-check-trustdb", "1");
        if (err) {
            // ignore error, but log a warning
            qCWarning(QGPGME_LOG) << "Setting context flag no-auto-check-trustdb failed:" << err;
        }
    }

    std::vector<Key> keys;
    KeyListResult r = do_list_keys(ctx, keys);
    std::sort(keys.begin(), keys.end(), ByFingerprint<std::less>());

    std::vector<Key> sec;
    std::copy_if(keys.begin(), keys.end(), std::back_inserter(sec), [](const Key &key) { return key.hasSecret(); });

    return std::make_tuple(r, keys, sec, QString(), Error());
}

}

Error QGpgMEListAllKeysJob::start(bool mergeKeys)
{
    run(std::bind(&list_keys, std::placeholders::_1, mergeKeys, options()));
    return Error();
}

KeyListResult QGpgMEListAllKeysJob::exec(std::vector<Key> &pub, std::vector<Key> &sec, bool mergeKeys)
{
    const result_type r = list_keys(context(), mergeKeys, options());
    resultHook(r);
    pub = std::get<1>(r);
    sec = std::get<2>(r);
    return std::get<0>(r);
}

void QGpgMEListAllKeysJob::resultHook(const result_type &tuple)
{
    mResult = std::get<0>(tuple);
}

#if 0
void QGpgMEListAllKeysJob::showErrorDialog(QWidget *parent, const QString &caption) const
{
    if (!mResult.error() || mResult.error().isCanceled()) {
        return;
    }
    const QString msg = i18n("<qt><p>An error occurred while fetching "
                             "the keys from the backend:</p>"
                             "<p><b>%1</b></p></qt>",
                             QString::fromLocal8Bit(mResult.error().asString()));
    KMessageBox::error(parent, msg, caption);
}
#endif
#include "qgpgmelistallkeysjob.moc"
