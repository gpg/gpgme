/*
    qgpgmebackend.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004,2005 Klarälvdalens Datakonsult AB
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

#include "qgpgmebackend.h"

#include "qgpgmegpgcardjob.h"

#include <gpgme++/error.h>
#include <gpgme++/engineinfo.h>

#include "protocol_p.h"

#include <QFile>
#include <QString>

const char QGpgME::QGpgMEBackend::OpenPGP[] = "OpenPGP";
const char QGpgME::QGpgMEBackend::SMIME[] = "SMIME";


QGpgME::QGpgMEBackend::QGpgMEBackend()
    : mCryptoConfig(nullptr),
      mOpenPGPProtocol(nullptr),
      mSMIMEProtocol(nullptr)
{
    GpgME::initializeLibrary();
}

QGpgME::QGpgMEBackend::~QGpgMEBackend()
{
    delete mCryptoConfig; mCryptoConfig = nullptr;
    delete mOpenPGPProtocol; mOpenPGPProtocol = nullptr;
    delete mSMIMEProtocol; mSMIMEProtocol = nullptr;
}

QString QGpgME::QGpgMEBackend::name() const
{
    return QStringLiteral("gpgme");
}

QString QGpgME::QGpgMEBackend::displayName() const
{
    return QStringLiteral("GpgME");
}

QGpgME::CryptoConfig *QGpgME::QGpgMEBackend::config() const
{
    if (!mCryptoConfig) {
        if (GpgME::hasFeature(GpgME::GpgConfEngineFeature, 0)) {
            mCryptoConfig = new QGpgMENewCryptoConfig;
        }
    }
    return mCryptoConfig;
}

QGpgME::GpgCardJob *QGpgME::QGpgMEBackend::gpgCardJob() const
{
    return new QGpgME::QGpgMEGpgCardJob();
}

static bool check(GpgME::Protocol proto, QString *reason)
{
    if (!GpgME::checkEngine(proto)) {
        return true;
    }
    if (!reason) {
        return false;
    }
    // error, check why:
#if 0
Port away from localised string or delete.
    const GpgME::EngineInfo ei = GpgME::engineInfo(proto);
    if (ei.isNull()) {
        *reason = i18n("GPGME was compiled without support for %1.", proto == GpgME::CMS ? QLatin1String("S/MIME") : QLatin1String("OpenPGP"));
    } else if (ei.fileName() && !ei.version()) {
        *reason = i18n("Engine %1 is not installed properly.", QFile::decodeName(ei.fileName()));
    } else if (ei.fileName() && ei.version() && ei.requiredVersion())
        *reason = i18n("Engine %1 version %2 installed, "
                       "but at least version %3 is required.",
                       QFile::decodeName(ei.fileName()), QLatin1String(ei.version()), QLatin1String(ei.requiredVersion()));
    else {
        *reason = i18n("Unknown problem with engine for protocol %1.", proto == GpgME::CMS ? QLatin1String("S/MIME") : QLatin1String("OpenPGP"));
    }
#endif
    return false;
}

bool QGpgME::QGpgMEBackend::checkForOpenPGP(QString *reason) const
{
    return check(GpgME::OpenPGP, reason);
}

bool QGpgME::QGpgMEBackend::checkForSMIME(QString *reason) const
{
    return check(GpgME::CMS, reason);
}

bool QGpgME::QGpgMEBackend::checkForProtocol(const char *name, QString *reason) const
{
    if (qstricmp(name, OpenPGP) == 0) {
        return check(GpgME::OpenPGP, reason);
    }
    if (qstricmp(name, SMIME) == 0) {
        return check(GpgME::CMS, reason);
    }
    if (reason) {
        *reason = QStringLiteral("Unsupported protocol \"%1\"").arg(QLatin1String(name));
    }
    return false;
}

QGpgME::Protocol *QGpgME::QGpgMEBackend::openpgp() const
{
    if (!mOpenPGPProtocol)
        if (checkForOpenPGP()) {
            mOpenPGPProtocol = new ::Protocol(GpgME::OpenPGP);
        }
    return mOpenPGPProtocol;
}

QGpgME::Protocol *QGpgME::QGpgMEBackend::smime() const
{
    if (!mSMIMEProtocol)
        if (checkForSMIME()) {
            mSMIMEProtocol = new ::Protocol(GpgME::CMS);
        }
    return mSMIMEProtocol;
}

QGpgME::Protocol *QGpgME::QGpgMEBackend::protocol(const char *name) const
{
    if (qstricmp(name, OpenPGP) == 0) {
        return openpgp();
    }
    if (qstricmp(name, SMIME) == 0) {
        return smime();
    }
    return nullptr;
}

bool QGpgME::QGpgMEBackend::supportsProtocol(const char *name) const
{
    return qstricmp(name, OpenPGP) == 0 || qstricmp(name, SMIME) == 0;
}

const char *QGpgME::QGpgMEBackend::enumerateProtocols(int i) const
{
    switch (i) {
    case 0: return OpenPGP;
    case 1: return SMIME;
    default: return nullptr;
    }
}

static QGpgME::QGpgMEBackend *gpgmeBackend;

QGpgME::CryptoConfig *QGpgME::cryptoConfig()
{
    if (!gpgmeBackend) {
        gpgmeBackend = new QGpgME::QGpgMEBackend();
    }
    return gpgmeBackend->config();

}

QGpgME::Protocol *QGpgME::openpgp()
{
    if (!gpgmeBackend) {
        gpgmeBackend = new QGpgME::QGpgMEBackend();
    }
    return gpgmeBackend->openpgp();
}

QGpgME::Protocol *QGpgME::smime()
{
    if (!gpgmeBackend) {
        gpgmeBackend = new QGpgME::QGpgMEBackend();
    }
    return gpgmeBackend->smime();
}

QGpgME::GpgCardJob *QGpgME::gpgCardJob ()
{
    if (!gpgmeBackend) {
        gpgmeBackend = new QGpgME::QGpgMEBackend();
    }
    return gpgmeBackend->gpgCardJob();
}
