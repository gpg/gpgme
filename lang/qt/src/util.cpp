/*
    util.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2022 g10 Code GmbH
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

#include "util.h"

#include "cleaner.h"
#include "qgpgme_debug.h"

#include <QFile>
#include <QFileInfo>
#include <QRandomGenerator>

#include <gpgme++/key.h>

#include <algorithm>
#include <functional>

std::vector<std::string> toStrings(const QStringList &l)
{
    std::vector<std::string> v;
    v.reserve(l.size());
    std::transform(std::begin(l), std::end(l),
                   std::back_inserter(v),
                   std::mem_fn(&QString::toStdString));
    return v;
}

QStringList toFingerprints(const std::vector<GpgME::Key> &keys)
{
    QStringList fprs;
    fprs.reserve(keys.size());
    std::transform(std::begin(keys), std::end(keys), std::back_inserter(fprs), [](const GpgME::Key &k) {
        return QString::fromLatin1(k.primaryFingerprint());
    });
    return fprs;
}

/**
 * Generates a string of random characters for the file names of temporary files.
 * Never use this for generating passwords or similar use cases requiring highly
 * secure random data.
 */
static QString getRandomCharacters(const int count)
{
    if (count < 0) {
        return {};
    }

    QString randomChars;
    randomChars.reserve(count);

    do {
        // get a 32-bit random number to generate up to 5 random characters from
        // the set {A-Z, a-z, 0-9}; set the highest bit for the break condition
        for (quint32 rnd = QRandomGenerator::global()->generate() | (1 << 31); rnd > 3; rnd = rnd >> 6)
        {
            // take the last 6 bits; ignore 62 and 63
            const char ch = rnd & ((1 << 6) - 1);
            if (ch < 26) {
                randomChars += QLatin1Char(ch + 'A');
            } else if (ch < 26 + 26) {
                randomChars += QLatin1Char(ch - 26 + 'a');
            } else if (ch < 26 + 26 + 10) {
                randomChars += QLatin1Char(ch - 26 - 26 + '0');
            }
            if (randomChars.size() >= count) {
                break;
            }
        }
    } while (randomChars.size() < count);

    return randomChars;
}

/**
 * Creates a temporary file name with extension \c .part for the given file name
 * \a fileName. The function makes sure that the created file name is not in use
 * at the time the file name is chosen.
 *
 * Example: For the file name "this.is.an.archive.tar.gpg" the temporary file name
 * "this.YHgf2tEl.is.an.archive.tar.gpg.part" could be returned.
 */
static QString createPartFileName(const QString &fileName)
{
    static const int maxAttempts = 10;

    const QFileInfo fi{fileName};
    const QString path = fi.path(); // path without trailing '/'
    const QString baseName = fi.baseName();
    const QString suffix = fi.completeSuffix();
    for (int attempt = 0; attempt < maxAttempts; ++attempt) {
        const QString candidate = (path + QLatin1Char('/')
                                   + baseName + QLatin1Char('.')
                                   + getRandomCharacters(8) + QLatin1Char('.')
                                   + suffix
                                   + QLatin1String(".part"));
        if (!QFile::exists(candidate)) {
            return candidate;
        }
    }

    qCWarning(QGPGME_LOG) << __func__ << "- Failed to create temporary file name for" << fileName;
    return {};
}

PartialFileGuard::PartialFileGuard(const QString &fileName)
    : mFileName{fileName}
    , mTempFileName{createPartFileName(fileName)}
{
    qCDebug(QGPGME_LOG) << __func__ << "- Using temporary file name" << mTempFileName;
}

PartialFileGuard::~PartialFileGuard()
{
    if (!mTempFileName.isEmpty()) {
        Cleaner::removeFile(mTempFileName);
    }
}

QString PartialFileGuard::tempFileName() const
{
    return mTempFileName;
}

bool PartialFileGuard::commit()
{
    if (mTempFileName.isEmpty()) {
        qCWarning(QGPGME_LOG) << "PartialFileGuard::commit: Called more than once";
        return false;
    }
    const bool success = QFile::rename(mTempFileName, mFileName);
    if (success) {
        qCDebug(QGPGME_LOG) << __func__ << "- Renamed" << mTempFileName << "to" << mFileName;
        mTempFileName.clear();
    } else {
        qCDebug(QGPGME_LOG) << __func__ << "- Renaming" << mTempFileName << "to" << mFileName << "failed";
    }
    return success;
}
