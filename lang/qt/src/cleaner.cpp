/*
    cleaner.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2023 g10 Code GmbH
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

#include "cleaner.h"

#include <qgpgme_debug.h>

#include <QCoreApplication>
#include <QFile>

#include <chrono>

static const auto timeout = std::chrono::seconds{10};

static bool remove_file(const QString &filePath)
{
    if (filePath.isEmpty()) {
        qCWarning(QGPGME_LOG) << __func__ << "- called with empty file path";
        return true;
    }
    if (QFile::exists(filePath)) {
        qCDebug(QGPGME_LOG) << __func__ << "- Removing file" << filePath;
        if (!QFile::remove(filePath)) {
            qCDebug(QGPGME_LOG) << __func__ << "- Removing file" << filePath << "failed";
            return false;
        }
    } else {
        qCDebug(QGPGME_LOG) << __func__ << "- File" << filePath << "doesn't exist";
    }
    return true;
}

void Cleaner::removeFile(const QString &filePath)
{
    if (!remove_file(filePath)) {
        // use invokeMethod because we might not be called from the GUI thread
        // but we want to delegate the Cleaner's clean-up to the application instance
        QMetaObject::invokeMethod(qApp, [filePath]() {
            new Cleaner{filePath, qApp};
        }, Qt::QueuedConnection);
    }
}

Cleaner::Cleaner(const QString &filePath, QObject *parent)
    : QObject{parent}
    , mFilePath{filePath}
{
    qCDebug(QGPGME_LOG) << this << __func__ << filePath;
    mTimer.setSingleShot(true);
    mTimer.callOnTimeout([this]() {
        if (remove_file(mFilePath)) {
            mFilePath.clear();
            deleteLater();
        } else {
            mTimer.start(timeout);
        }
    });
    mTimer.start(timeout);
}

Cleaner::~Cleaner()
{
    qCDebug(QGPGME_LOG) << this << __func__;
    if (!mFilePath.isEmpty()) {
        remove_file(mFilePath);
    }
}

#include "cleaner.moc"
