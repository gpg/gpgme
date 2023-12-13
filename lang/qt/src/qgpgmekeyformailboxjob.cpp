/*
    qgpgmekeyformailboxjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
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

#include "qgpgmekeyformailboxjob.h"
#include "qgpgmekeylistjob.h"

#include <QStringList>

#include <tuple>

using namespace GpgME;
using namespace QGpgME;

QGpgMEKeyForMailboxJob::QGpgMEKeyForMailboxJob(Context *context)
    : mixin_type(context)
{
    lateInitialization();
}

QGpgMEKeyForMailboxJob::~QGpgMEKeyForMailboxJob() {}

static bool keyIsOk(const Key k)
{
    return !k.isExpired() && !k.isRevoked() && !k.isInvalid() && !k.isDisabled();
}

static bool uidIsOk(const UserID uid)
{
    return keyIsOk(uid.parent()) && !uid.isRevoked() && !uid.isInvalid();
}

static bool subkeyIsOk(const Subkey s)
{
    return !s.isRevoked() && !s.isInvalid() && !s.isDisabled();
}

static QGpgMEKeyForMailboxJob::result_type do_work(Context *ctx, const QString &mailbox, bool canEncrypt)
{
    /* Do a Keylisting. */
    ctx->setKeyListMode(GpgME::Locate | GpgME::Signatures | GpgME::Validate);
    std::vector<Key> keys;
    QGpgMEKeyListJob *keylist = new QGpgMEKeyListJob(ctx);

    KeyListResult result = keylist->exec(QStringList() << mailbox, false, keys);

    if (result.error()) {
        return std::make_tuple(result, Key(), UserID(), QString(), Error());
    }

    // This should ideally be decided by GnuPG and this Job changed
    // to just call the according API in GpgME
    // See: https://bugs.gnupg.org/gnupg/issue2359
    Key keyC;
    UserID uidC;
    for (const Key &k : keys) {
        if (canEncrypt && !k.canEncrypt()) {
            continue;
        }
        /* First get the uid that matches the mailbox */
        for (const UserID &u : k.userIDs()) {
            if (QString::fromUtf8(u.email()).toLower() == mailbox.toLower()) {
                if (uidC.isNull()) {
                    keyC = k;
                    uidC = u;
                } else if ((!uidIsOk(uidC) && uidIsOk(u)) || uidC.validity() < u.validity()) {
                    /* Validity of the new key is better. */
                    uidC = u;
                    keyC = k;
                } else if (uidC.validity() == u.validity() && uidIsOk(u)) {
                    /* Both are the same check which one is newer. */
                    time_t oldTime = 0;
                    for (const Subkey &s : keyC.subkeys()) {
                        if ((canEncrypt && s.canEncrypt()) && subkeyIsOk(s)) {
                            oldTime = s.creationTime();
                        }
                    }
                    time_t newTime = 0;
                    for (const Subkey &s : k.subkeys()) {
                        if ((canEncrypt && s.canEncrypt()) && subkeyIsOk(s)) {
                            newTime = s.creationTime();
                        }
                    }
                    if (newTime > oldTime) {
                        uidC = u;
                        keyC = k;
                    }
                }
            }
        }
    }
    return std::make_tuple(result, keyC, uidC, QString(), Error());
}

Error QGpgMEKeyForMailboxJob::start(const QString &mailbox, bool canEncrypt)
{
    run(std::bind(&do_work, std::placeholders::_1, mailbox, canEncrypt));
    return Error();
}

KeyListResult QGpgMEKeyForMailboxJob::exec(const QString &mailbox, bool canEncrypt, Key &key, UserID &uid)
{
    const result_type r = do_work(context(), mailbox, canEncrypt);
    resultHook(r);
    key = std::get<1>(r);
    uid = std::get<2>(r);
    return std::get<0>(r);
}

#include "qgpgmekeyformailboxjob.moc"
