/* t-support.h

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
#ifndef T_SUPPORT_H
#define T_SUPPORT_H

#include <gpgme++/interfaces/passphraseprovider.h>
#include <QObject>
#include <QTest>

#include <gpg-error.h>

namespace GpgME
{
class Context;
}

namespace QGpgME
{
class Job;
}

/// generic variant of QVERIFY returning \a returnValue on failure
#define VERIFY_OR_RETURN_VALUE(statement, returnValue) \
do {\
    if (!QTest::qVerify(static_cast<bool>(statement), #statement, "", __FILE__, __LINE__))\
        return returnValue;\
} while (false)

/// generic variant of QCOMPARE returning \a returnValue on failure
#define COMPARE_OR_RETURN_VALUE(actual, expected, returnValue) \
do {\
    if (!QTest::qCompare(actual, expected, #actual, #expected, __FILE__, __LINE__))\
        return returnValue;\
} while (false)

/// variant of QVERIFY returning a default constructed object on failure
#define VERIFY_OR_OBJECT(statement) VERIFY_OR_RETURN_VALUE(statement, {})

/// variant of QCOMPARE returning a default constructed object on failure
#define COMPARE_OR_OBJECT(actual, expected) COMPARE_OR_RETURN_VALUE(actual, expected, {})

/// variant of QVERIFY returning \c false on failure
#define VERIFY_OR_FALSE(statement) VERIFY_OR_RETURN_VALUE(statement, false)

/// variant of QCOMPARE returning \c false on failure
#define COMPARE_OR_FALSE(actual, expected) COMPARE_OR_RETURN_VALUE(actual, expected, false)

namespace QTest
{
template <>
inline char *toString(const std::string &s)
{
    return QTest::toString(s.c_str());
}
}

namespace GpgME
{
class TestPassphraseProvider : public PassphraseProvider
{
public:
    char *getPassphrase(const char * /*useridHint*/, const char * /*description*/,
                        bool /*previousWasBad*/, bool &/*canceled*/) override
    {
        char *ret;
        gpgrt_asprintf(&ret, "abc");
        return ret;
    }
};
} // namespace GpgME

void killAgent(const QString &dir = qgetenv("GNUPGHOME"));
/* Is the passphrase Provider / loopback Supported */
bool loopbackSupported();

class QGpgMETest : public QObject
{
    Q_OBJECT

Q_SIGNALS:
    void asyncDone();

protected:
    static bool doOnlineTests();

    bool copyKeyrings(const QString &from, const QString& to);

    bool importSecretKeys(const char *keyData, int expectedKeys = 1);

    void hookUpPassphraseProvider(GpgME::Context *context);
    void hookUpPassphraseProvider(QGpgME::Job *job);

public Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();

private:
    GpgME::TestPassphraseProvider mPassphraseProvider;
};

/* Timeout, in milliseconds, for use with QSignalSpy to wait on
   signals.  */
#define QSIGNALSPY_TIMEOUT	60000

#endif // T_SUPPORT_H
