/* t-config.cpp

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
#include <QTemporaryDir>
#include "t-support.h"
#include "protocol.h"
#include "cryptoconfig.h"
#include <gpgme++/engineinfo.h>

#include <unistd.h>

using namespace QGpgME;

class CryptoConfigTest: public QGpgMETest
{
    Q_OBJECT

private Q_SLOTS:
    void testDefault()
    {
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.2.0") {
            // We are using compliance here and other options might also
            // be unsupported in older versions.
            return;
        }
        auto conf = cryptoConfig();
        QVERIFY(conf);
        auto entry = conf->entry(QStringLiteral("gpg"), QStringLiteral("compliance"));
        QVERIFY(entry);
        const auto defaultValue = entry->defaultValue().toString();
        QCOMPARE(defaultValue, QStringLiteral("gnupg"));

        entry->setStringValue("de-vs");
        conf->sync(true);
        conf->clear();
        entry = conf->entry(QStringLiteral("gpg"), QStringLiteral("compliance"));
        QCOMPARE(entry->stringValue(), QStringLiteral("de-vs"));

        entry->resetToDefault();
        conf->sync(true);
        conf->clear();
        entry = conf->entry(QStringLiteral("gpg"), QStringLiteral("compliance"));
        QCOMPARE(entry->stringValue(), defaultValue);
    }

    void initTestCase()
    {
        QGpgMETest::initTestCase();
        const QString gpgHome = qgetenv("GNUPGHOME");
        qputenv("GNUPGHOME", mDir.path().toUtf8());
        QVERIFY(mDir.isValid());
    }
private:
    QTemporaryDir mDir;

};

QTEST_MAIN(CryptoConfigTest)

#include "t-config.moc"
