/*
    dn.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004 Klarälvdalens Datakonsult AB
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
#ifndef QGPGME_DN_H
#define QGPGME_DN_H

#include "qgpgme_export.h"

#include <QString>
#include <QStringList>

#include <QVector>

namespace QGpgME
{

/**
   @short DN parser and reorderer
*/
class QGPGME_EXPORT DN
{
public:
    class Attribute;
    typedef QVector<Attribute> AttributeList;
    typedef AttributeList::const_iterator const_iterator;

    DN();
    explicit DN(const QString &dn);
    explicit DN(const char *utf8DN);
    DN(const DN &other);
    ~DN();

    const DN &operator=(const DN &other);

    /** @return the value in rfc-2253-escaped form */
    static QString escape(const QString &value);

    /** @return the DN in a reordered form, according to the settings in
        the [DN] group of the application's config file */
    QString prettyDN() const;
    /** @return the DN in the original form */
    QString dn() const;
    /**
       \overload
       Uses \a sep as separator (default: ,)
    */
    QString dn(const QString &sep) const;

    QString operator[](const QString &attr) const;

    void append(const Attribute &attr);

    const_iterator begin() const;
    const_iterator end() const;

    /** Set the order in which prettyDN will reorder the Attirbutes. */
    void setAttributeOrder(const QStringList &order) const;

    /** Get the used attribute order. */
    const QStringList & attributeOrder() const;

private:
    void detach();
private:
    class Private;
    Private *d;
};

class QGPGME_EXPORT DN::Attribute
{
public:
    typedef DN::AttributeList List;

    explicit Attribute(const QString &name = QString(), const QString &value = QString())
        : mName(name.toUpper()), mValue(value) {}
    Attribute(const Attribute &other)
        : mName(other.name()), mValue(other.value()) {}

    const Attribute &operator=(const Attribute &other)
    {
        if (this != &other) {
            mName = other.name();
            mValue = other.value();
        }
        return *this;
    }

    const QString &name() const
    {
        return mName;
    }
    const QString &value() const
    {
        return mValue;
    }

    void setValue(const QString &value)
    {
        mValue = value;
    }

private:
    QString mName;
    QString mValue;
};
} // namespace QGpgME
#endif // QGPGME_DN_H
