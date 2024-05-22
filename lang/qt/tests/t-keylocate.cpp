/* t-keylocate.cpp

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
#include <QDebug>
#include <QTest>
#include <QSignalSpy>
#include <QTemporaryDir>
#include "keylistjob.h"
#include "protocol.h"
#include <gpgme++/keylistresult.h>
#include <gpgme++/engineinfo.h>

#include "t-support.h"

using namespace QGpgME;
using namespace GpgME;

class KeyLocateTest : public QGpgMETest
{
    Q_OBJECT

private Q_SLOTS:

#ifdef DO_ONLINE_TESTS
    void testDaneKeyLocate()
    {
        QTemporaryDir dir;
        const QString oldHome = qgetenv("GNUPGHOME");
        qputenv("GNUPGHOME", dir.path().toUtf8());
        /* Could do this with gpgconf but this is not a gpgconf test ;-) */
        QFile conf(dir.path() + QStringLiteral("/gpg.conf"));
        QVERIFY(conf.open(QIODevice::WriteOnly));
        conf.write("auto-key-locate dane");
        conf.close();

        auto *job = openpgp()->locateKeysJob();
        mTestpattern = QStringLiteral("wk@gnupg.org");
        connect(job, &KeyListJob::result, job, [this, job](KeyListResult result, std::vector<Key> keys, QString, Error)
        {
            QVERIFY(!result.error());
            QVERIFY(keys.size() == 1);

            Key k = keys.front();
            QVERIFY(k.numUserIDs());
            bool found = false;
            for (const UserID &uid : k.userIDs()) {
                const QString mailBox = QString::fromUtf8(uid.email());
                if (mTestpattern.toLower() == mailBox.toLower()) {
                    found = true;
                }
            }
            QVERIFY(found);
            Q_EMIT asyncDone();
        });
        job->start(QStringList() << mTestpattern);
        QSignalSpy spy (this, SIGNAL(asyncDone()));
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));
        qputenv("GNUPGHOME", oldHome.toUtf8());
    }
#endif

    void testKeyLocateSingle()
    {
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.0.10") {
            return;
        }
        auto *job = openpgp()->locateKeysJob();
        mTestpattern = QStringLiteral("alfa@example.net");

        connect(job, &KeyListJob::result, job, [this, job](KeyListResult result, std::vector<Key> keys, QString, Error)
        {
            QVERIFY(!result.isNull());
            QVERIFY(!result.isTruncated());
            QVERIFY(!result.error());
            QVERIFY(keys.size() == 1);

            Key k = keys.front();
            QVERIFY(k.numUserIDs());
            bool found = false;
            for (const UserID &uid : k.userIDs()) {
                const QString mailBox = QString::fromUtf8(uid.email());
                if (mTestpattern.toLower() == mailBox.toLower()) {
                    found = true;
                }
            }
            QVERIFY(found);
            Q_EMIT asyncDone();
        });
        job->start(QStringList() << mTestpattern);
        QSignalSpy spy (this, SIGNAL(asyncDone()));
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));
    }

private:
    QString mTestpattern;
};

QTEST_MAIN(KeyLocateTest)

#include "t-keylocate.moc"
