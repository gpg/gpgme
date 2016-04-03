/*
    qgpgmelistallkeysjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004,2008 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 Intevation GmbH

    Libkleopatra is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.

    Libkleopatra is distributed in the hope that it will be useful,
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

#include "qgpgmelistallkeysjob.h"

#include "predicates.h"

#include "key.h"
#include "context.h"
#include "keylistresult.h"
#include <gpg-error.h>

#include <algorithm>

#include <cstdlib>
#include <cstring>
#include <cassert>

using namespace QGpgME;
using namespace GpgME;
using namespace boost;

QGpgMEListAllKeysJob::QGpgMEListAllKeysJob(Context *context)
    : mixin_type(context),
      mResult()
{
    lateInitialization();
}

QGpgMEListAllKeysJob::~QGpgMEListAllKeysJob() {}

static KeyListResult do_list_keys(Context *ctx, std::vector<Key> &keys, bool secretOnly)
{

    const char **pat = 0;
    if (const Error err = ctx->startKeyListing(pat, secretOnly)) {
        return KeyListResult(0, err);
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

namespace
{

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

}

static void merge_keys(std::vector<Key> &merged, std::vector<Key> &pub, std::vector<Key> &sec)
{
    merged.reserve(pub.size() + sec.size());

    std::merge(pub.begin(), pub.end(),
               sec.begin(), sec.end(),
               std::back_inserter(merged),
               _detail::ByFingerprint<std::less>());

    merged.erase(unique_by_merge(merged.begin(), merged.end(), _detail::ByFingerprint<std::equal_to>()),
                 merged.end());
}

static QGpgMEListAllKeysJob::result_type list_keys(Context *ctx, bool mergeKeys)
{
    std::vector<Key> pub, sec, merged;
    KeyListResult r;

    r.mergeWith(do_list_keys(ctx, pub, false));
    std::sort(pub.begin(), pub.end(), _detail::ByFingerprint<std::less>());

    r.mergeWith(do_list_keys(ctx, sec, true));
    std::sort(sec.begin(), sec.end(), _detail::ByFingerprint<std::less>());

    if (mergeKeys) {
        merge_keys(merged, pub, sec);
    } else {
        merged.swap(pub);
    }
    return boost::make_tuple(r, merged, sec, QString(), Error());
}

Error QGpgMEListAllKeysJob::start(bool mergeKeys)
{
    run(boost::bind(&list_keys, _1, mergeKeys));
    return Error();
}

KeyListResult QGpgMEListAllKeysJob::exec(std::vector<Key> &pub, std::vector<Key> &sec, bool mergeKeys)
{
    const result_type r = list_keys(context(), mergeKeys);
    resultHook(r);
    pub = get<1>(r);
    sec = get<2>(r);
    return get<0>(r);
}

void QGpgMEListAllKeysJob::resultHook(const result_type &tuple)
{
    mResult = get<0>(tuple);
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
