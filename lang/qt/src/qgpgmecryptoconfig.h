/*
    qgpgmecryptoconfig.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 Intevation GmbH

    Libkleopatra is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.

    Libkleopatra is distributed in the hope that it will be useful,
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

#ifndef QGPGME_QGPGMECRYPTOCONFIG_H
#define QGPGME_QGPGMECRYPTOCONFIG_H

#include "qgpgme_export.h"
#include "cryptoconfig.h"

#include <QHash>
#include <QStringList>
#include <QObject>
#include <QVariant>
#include <QPointer>

#include <vector>
#include <utility>

class QGpgMECryptoConfigComponent;
class QGpgMECryptoConfigEntry;
/**
 * CryptoConfig implementation around the gpgconf command-line tool
 * For method docu, see kleo/cryptoconfig.h
 */
class QGPGME_EXPORT QGpgMECryptoConfig : public QObject, public QGpgME::CryptoConfig
{

    Q_OBJECT
public:

    static QString gpgConfPath();
    /**
     * Constructor
     */
    QGpgMECryptoConfig();
    virtual ~QGpgMECryptoConfig();

    QStringList componentList() const Q_DECL_OVERRIDE;

    QGpgME::CryptoConfigComponent *component(const QString &name) const Q_DECL_OVERRIDE;

    void clear() Q_DECL_OVERRIDE;
    void sync(bool runtime) Q_DECL_OVERRIDE;

private Q_SLOTS:
    void slotCollectStdOut();
private:
    /// @param showErrors if true, a messagebox will be shown if e.g. gpgconf wasn't found
    void runGpgConf(bool showErrors);

private:
    std::vector<std::pair<QString, QGpgMECryptoConfigComponent *> > mComponentsNaturalOrder;
    QHash<QString, QGpgMECryptoConfigComponent *> mComponentsByName;
    bool mParsed;
};

class QGpgMECryptoConfigGroup;

/// For docu, see kleo/cryptoconfig.h
class QGpgMECryptoConfigComponent : public QObject, public QGpgME::CryptoConfigComponent
{

    Q_OBJECT
public:
    QGpgMECryptoConfigComponent(QGpgMECryptoConfig *, const QString &name, const QString &description);
    ~QGpgMECryptoConfigComponent();

    QString name() const Q_DECL_OVERRIDE
    {
        return mName;
    }
    QString iconName() const Q_DECL_OVERRIDE
    {
        return mName;
    }
    QString description() const Q_DECL_OVERRIDE
    {
        return mDescription;
    }
    QStringList groupList() const Q_DECL_OVERRIDE;
    QGpgME::CryptoConfigGroup *group(const QString &name) const Q_DECL_OVERRIDE;

    void sync(bool runtime);

private Q_SLOTS:
    void slotCollectStdOut();
private:
    void runGpgConf();

private:
    std::vector< std::pair<QString, QGpgMECryptoConfigGroup *> > mGroupsNaturalOrder;
    QHash<QString, QGpgMECryptoConfigGroup *> mGroupsByName;
    QString mName;
    QString mDescription;
    QGpgMECryptoConfigGroup *mCurrentGroup; // during parsing
    QString mCurrentGroupName; // during parsing
};

class QGpgMECryptoConfigGroup : public QGpgME::CryptoConfigGroup
{

public:
    QGpgMECryptoConfigGroup(QGpgMECryptoConfigComponent *comp, const QString &name, const QString &description, int level);
    ~QGpgMECryptoConfigGroup();

    QString name() const Q_DECL_OVERRIDE
    {
        return mName;
    }
    QString iconName() const Q_DECL_OVERRIDE
    {
        return QString();
    }
    QString description() const Q_DECL_OVERRIDE
    {
        return mDescription;
    }
    QString path() const Q_DECL_OVERRIDE
    {
        return mComponent->name() + QLatin1Char('/') + mName;
    }
    QGpgME::CryptoConfigEntry::Level level() const Q_DECL_OVERRIDE
    {
        return mLevel;
    }
    QStringList entryList() const Q_DECL_OVERRIDE;
    QGpgME::CryptoConfigEntry *entry(const QString &name) const Q_DECL_OVERRIDE;

private:
    friend class QGpgMECryptoConfigComponent; // it adds the entries
    QPointer<QGpgMECryptoConfigComponent> mComponent;
    std::vector< std::pair<QString, QGpgMECryptoConfigEntry *> > mEntriesNaturalOrder;
    QHash<QString, QGpgMECryptoConfigEntry *> mEntriesByName;
    QString mName;
    QString mDescription;
    QGpgME::CryptoConfigEntry::Level mLevel;
};

class QGpgMECryptoConfigEntry : public QGpgME::CryptoConfigEntry
{
public:
    QGpgMECryptoConfigEntry(QGpgMECryptoConfigGroup *group, const QStringList &parsedLine);
    ~QGpgMECryptoConfigEntry();

    QString name() const Q_DECL_OVERRIDE
    {
        return mName;
    }
    QString description() const Q_DECL_OVERRIDE
    {
        return mDescription;
    }
    QString path() const Q_DECL_OVERRIDE
    {
        return mGroup->path() + QLatin1Char('/') + mName;
    }
    bool isOptional() const Q_DECL_OVERRIDE;
    bool isReadOnly() const Q_DECL_OVERRIDE;
    bool isList() const Q_DECL_OVERRIDE;
    bool isRuntime() const Q_DECL_OVERRIDE;
    Level level() const Q_DECL_OVERRIDE
    {
        return static_cast<Level>(mLevel);
    }
    ArgType argType() const Q_DECL_OVERRIDE
    {
        return static_cast<ArgType>(mArgType);
    }
    bool isSet() const Q_DECL_OVERRIDE;
    bool boolValue() const Q_DECL_OVERRIDE;
    QString stringValue() const Q_DECL_OVERRIDE;
    int intValue() const Q_DECL_OVERRIDE;
    unsigned int uintValue() const Q_DECL_OVERRIDE;
    QUrl urlValue() const Q_DECL_OVERRIDE;
    unsigned int numberOfTimesSet() const Q_DECL_OVERRIDE;
    std::vector<int> intValueList() const Q_DECL_OVERRIDE;
    std::vector<unsigned int> uintValueList() const Q_DECL_OVERRIDE;
    QList<QUrl> urlValueList() const Q_DECL_OVERRIDE;
    void resetToDefault() Q_DECL_OVERRIDE;
    void setBoolValue(bool) Q_DECL_OVERRIDE;
    void setStringValue(const QString &) Q_DECL_OVERRIDE;
    void setIntValue(int) Q_DECL_OVERRIDE;
    void setUIntValue(unsigned int) Q_DECL_OVERRIDE;
    void setURLValue(const QUrl &) Q_DECL_OVERRIDE;
    void setNumberOfTimesSet(unsigned int) Q_DECL_OVERRIDE;
    void setIntValueList(const std::vector<int> &) Q_DECL_OVERRIDE;
    void setUIntValueList(const std::vector<unsigned int> &) Q_DECL_OVERRIDE;
    void setURLValueList(const QList<QUrl> &) Q_DECL_OVERRIDE;
    bool isDirty() const Q_DECL_OVERRIDE
    {
        return mDirty;
    }

    void setDirty(bool b);
    QString outputString() const;

protected:
    bool isStringType() const;
    QVariant stringToValue(const QString &value, bool unescape) const;
    QString toString(bool escape) const;
private:
    QGpgMECryptoConfigGroup *mGroup;
    QString mName;
    QString mDescription;
    QVariant mDefaultValue;
    QVariant mValue;
    uint mFlags : 8; // bitfield with 8 bits
    uint mLevel : 3; // max is 4 (2, in fact) -> 3 bits
    uint mRealArgType : 6; // max is 33 -> 6 bits
    uint mArgType : 3; // max is 6 (ArgType enum) -> 3 bits;
    uint mDirty : 1;
    uint mSet : 1;
};

#endif /* QGPGME_QGPGMECRYPTOCONFIG_H */
