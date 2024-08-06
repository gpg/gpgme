/* t-disablekey.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2024 g10 Code GmbH
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

#include "t-support.h"

#include "quickjob.h"
#include "debug.h"
#include "keylistjob.h"
#include "protocol.h"

#include <gpgme++/engineinfo.h>
#include <gpgme++/keylistresult.h>

#include <QDebug>
#include <QSignalSpy>
#include <QTest>

using namespace QGpgME;
using namespace GpgME;

class DisableKeyTest: public QGpgMETest
{
    Q_OBJECT

    Key getTestKey()
    {
        const std::unique_ptr<KeyListJob> job{openpgp()->keyListJob(false, true, true)};
        std::vector<GpgME::Key> keys;
        KeyListResult result = job->exec({QStringLiteral("alfa@example.net")}, false, keys);
        VERIFY_OR_OBJECT(!result.error());
        VERIFY_OR_OBJECT(keys.size() == 1);
        return keys.front();
    }

private Q_SLOTS:

    void testDisableAndEnableKey()
    {
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.4.6") {
            QSKIP("gpg does not yet support the --quick-set-ownertrust command");
        }

        Key key = getTestKey();
        QVERIFY(!key.isNull());
        QVERIFY(!key.isDisabled());

        {
            const std::unique_ptr<QuickJob> job{openpgp()->quickJob()};
            connect(job.get(), &QuickJob::result, this, [this](Error e) {
                if (e) {
                    qDebug() <<  "Error in result:" << e;
                }
                QVERIFY(!e);
                Q_EMIT asyncDone();
            });
            job->startSetKeyEnabled(key, false);
            QSignalSpy spy{this, SIGNAL(asyncDone())};
            QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));
        }
        key = getTestKey();
        QVERIFY(!key.isNull());
        QVERIFY(key.isDisabled());

        {
            const std::unique_ptr<QuickJob> job{openpgp()->quickJob()};
            connect(job.get(), &QuickJob::result, this, [this](Error e) {
                if (e) {
                    qDebug() <<  "Error in result:" << e;
                }
                QVERIFY(!e);
                Q_EMIT asyncDone();
            });
            job->startSetKeyEnabled(key, true);
            QSignalSpy spy{this, SIGNAL(asyncDone())};
            QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));
        }
        key = getTestKey();
        QVERIFY(!key.isNull());
        QVERIFY(!key.isDisabled());
    }
};

QTEST_MAIN(DisableKeyTest)

#include "t-disablekey.moc"
