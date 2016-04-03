#include <QDebug>
#include <QTest>
#include "keylistjob.h"
#include "qgpgmebackend.h"
#include "keylistresult.h"

using namespace QGpgME;

class KeyListTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:

    void testSingleKeyListSync()
    {
        KeyListJob *job = openpgp()->keyListJob(false, false, false);
        std::vector<GpgME::Key> keys;
        GpgME::KeyListResult result = job->exec(QStringList() << QStringLiteral("alfa@example.net"),
                                                false, keys);
        Q_ASSERT (!result.error());
        Q_ASSERT (keys.size() == 1);
        const QString kId = QLatin1String(keys.front().keyID());
        Q_ASSERT (kId == QStringLiteral("2D727CC768697734"));
    }
};

QTEST_MAIN(KeyListTest)

#include "t-keylist.moc"
