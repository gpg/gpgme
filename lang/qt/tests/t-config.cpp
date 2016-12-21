/* t-config.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2016 Intevation GmbH

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

#include <QDebug>
#include <QTest>
#include <QTemporaryDir>
#include "t-support.h"
#include "protocol.h"
#include "cryptoconfig.h"
#include <unistd.h>

using namespace QGpgME;

class CryptoConfigTest: public QGpgMETest
{
    Q_OBJECT

private Q_SLOTS:
    void testKeyserver()
    {
        // Repeatedly set a config value and clear it
        // this war broken at some point so it gets a
        // unit test.
        for (int i = 0; i < 10; i++) {
            auto conf = cryptoConfig();
            Q_ASSERT (conf);
            auto entry = conf->entry(QStringLiteral("gpg"),
                    QStringLiteral("Keyserver"),
                    QStringLiteral("keyserver"));
            Q_ASSERT(entry);
            const QString url(QStringLiteral("hkp://foo.bar.baz"));
            entry->setStringValue(url);
            conf->sync(false);
            conf->clear();
            entry = conf->entry(QStringLiteral("gpg"),
                    QStringLiteral("Keyserver"),
                    QStringLiteral("keyserver"));
            QCOMPARE (entry->stringValue(), url);
            entry->setStringValue(QString());
            conf->sync(false);
            conf->clear();
            entry = conf->entry(QStringLiteral("gpg"),
                    QStringLiteral("Keyserver"),
                    QStringLiteral("keyserver"));
            QCOMPARE (entry->stringValue(), QString());
        }
    }

    void initTestCase()
    {
        QGpgMETest::initTestCase();
        const QString gpgHome = qgetenv("GNUPGHOME");
        qputenv("GNUPGHOME", mDir.path().toUtf8());
        Q_ASSERT(mDir.isValid());
    }
private:
    QTemporaryDir mDir;

};

QTEST_MAIN(CryptoConfigTest)

#include "t-config.moc"
