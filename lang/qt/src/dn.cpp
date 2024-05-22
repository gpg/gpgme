/*
    dn.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004 Klarälvdalens Datakonsult AB
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

#include "dn.h"

#include <gpg-error.h>

static const struct {
    const char *name;
    const char *oid;
} oidmap[] = {
    // keep them ordered by oid:
    { "SP", "ST" }, // hack to show the Sphinx-required/desired SP for
    // StateOrProvince, otherwise known as ST or even S
    { "NameDistinguisher", "0.2.262.1.10.7.20" },
    { "EMAIL", "1.2.840.113549.1.9.1" },
    { "SN", "2.5.4.4" },
    { "SerialNumber", "2.5.4.5" },
    { "T", "2.5.4.12" },
    { "D", "2.5.4.13" },
    { "BC", "2.5.4.15" },
    { "ADDR", "2.5.4.16" },
    { "PC", "2.5.4.17" },
    { "GN", "2.5.4.42" },
    { "Pseudo", "2.5.4.65" },
};
static const unsigned int numOidMaps = sizeof oidmap / sizeof * oidmap;

class QGpgME::DN::Private
{
public:
    Private() : mRefCount(0) {}
    Private(const Private &other)
        : attributes(other.attributes),
          reorderedAttributes(other.reorderedAttributes),
          order{"CN", "L", "_X_", "OU", "O", "C"},
          mRefCount(0)
    {
    }

    int ref()
    {
        return ++mRefCount;
    }

    int unref()
    {
        if (--mRefCount <= 0) {
            delete this;
            return 0;
        } else {
            return mRefCount;
        }
    }

    int refCount() const
    {
        return mRefCount;
    }

    DN::Attribute::List attributes;
    DN::Attribute::List reorderedAttributes;
    QStringList order;
private:
    int mRefCount;
};

namespace
{
struct DnPair {
    char *key;
    char *value;
};
}

// copied from CryptPlug and adapted to work on DN::Attribute::List:

#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define hexdigitp(a) (digitp (a)                     \
                      || (*(a) >= 'A' && *(a) <= 'F')  \
                      || (*(a) >= 'a' && *(a) <= 'f'))
#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))

static char *
trim_trailing_spaces(char *string)
{
    char *p, *mark;

    for (mark = NULL, p = string; *p; p++) {
        if (isspace(*p)) {
            if (!mark) {
                mark = p;
            }
        } else {
            mark = NULL;
        }
    }
    if (mark) {
        *mark = '\0';
    }

    return string;
}

/* Parse a DN and return an array-ized one.  This is not a validating
   parser and it does not support any old-stylish syntax; gpgme is
   expected to return only rfc2253 compatible strings. */
static const unsigned char *
parse_dn_part(DnPair *array, const unsigned char *string)
{
    const unsigned char *s, *s1;
    size_t n;
    char *p;

    /* parse attributeType */
    for (s = string + 1; *s && *s != '='; s++)
        ;
    if (!*s) {
        return NULL;    /* error */
    }
    n = s - string;
    if (!n) {
        return NULL;    /* empty key */
    }
    p = (char *)malloc(n + 1);

    memcpy(p, string, n);
    p[n] = 0;
    trim_trailing_spaces((char *)p);
    // map OIDs to their names:
    for (unsigned int i = 0; i < numOidMaps; ++i)
        if (!strcasecmp((char *)p, oidmap[i].oid)) {
            free(p);
            gpgrt_asprintf(&p, "%s", oidmap[i].name);
            break;
        }
    array->key = p;
    string = s + 1;

    if (*string == '#') {
        /* hexstring */
        string++;
        for (s = string; hexdigitp(s); s++)
          ;
        n = s - string;
        if (!n || (n & 1)) {
            return NULL;    /* empty or odd number of digits */
        }
        n /= 2;
        array->value = p = (char *)malloc(n + 1);

        for (s1 = string; n; s1 += 2, n--) {
            *p++ = xtoi_2(s1);
        }
        *p = 0;
    } else {
        /* regular v3 quoted string */
        for (n = 0, s = string; *s; s++) {
            if (*s == '\\') {
                /* pair */
                s++;
                if (*s == ',' || *s == '=' || *s == '+'
                        || *s == '<' || *s == '>' || *s == '#' || *s == ';'
                        || *s == '\\' || *s == '\"' || *s == ' ') {
                    n++;
                } else if (hexdigitp(s) && hexdigitp(s + 1)) {
                    s++;
                    n++;
                } else {
                    return NULL;    /* invalid escape sequence */
                }
            } else if (*s == '\"') {
                return NULL;    /* invalid encoding */
            } else if (*s == ',' || *s == '=' || *s == '+'
                       || *s == '<' || *s == '>' || *s == '#' || *s == ';') {
                break;
            } else {
                n++;
            }
        }

        array->value = p = (char *)malloc(n + 1);

        for (s = string; n; s++, n--) {
            if (*s == '\\') {
                s++;
                if (hexdigitp(s)) {
                    *p++ = xtoi_2(s);
                    s++;
                } else {
                    *p++ = *s;
                }
            } else {
                *p++ = *s;
            }
        }
        *p = 0;
    }
    return s;
}

/* Parse a DN and return an array-ized one.  This is not a validating
   parser and it does not support any old-stylish syntax; gpgme is
   expected to return only rfc2253 compatible strings. */
static QGpgME::DN::Attribute::List
parse_dn(const unsigned char *string)
{
    if (!string) {
        return QVector<QGpgME::DN::Attribute>();
    }

    QVector<QGpgME::DN::Attribute> result;
    while (*string) {
        while (*string == ' ') {
            string++;
        }
        if (!*string) {
            break;    /* ready */
        }

        DnPair pair = { nullptr, nullptr };
        string = parse_dn_part(&pair, string);
        if (!string) {
            goto failure;
        }
        if (pair.key && pair.value)
            result.push_back(QGpgME::DN::Attribute(QString::fromUtf8(pair.key),
                                                 QString::fromUtf8(pair.value)));
        free(pair.key);
        free(pair.value);

        while (*string == ' ') {
            string++;
        }
        if (*string && *string != ',' && *string != ';' && *string != '+') {
            goto failure;    /* invalid delimiter */
        }
        if (*string) {
            string++;
        }
    }
    return result;

failure:
    return QVector<QGpgME::DN::Attribute>();
}

static QVector<QGpgME::DN::Attribute>
parse_dn(const QString &dn)
{
    return parse_dn((const unsigned char *)dn.toUtf8().data());
}

static QString dn_escape(const QString &s)
{
    QString result;
    for (unsigned int i = 0, end = s.length(); i != end; ++i) {
        const QChar ch = s[i];
        switch (ch.unicode()) {
        case ',':
        case '+':
        case '"':
        case '\\':
        case '<':
        case '>':
        case ';':
            result += QLatin1Char('\\');
        // fall through
        default:
            result += ch;
        }
    }
    return result;
}

static QString
serialise(const QVector<QGpgME::DN::Attribute> &dn, const QString &sep)
{
    QStringList result;
    for (QVector<QGpgME::DN::Attribute>::const_iterator it = dn.begin(); it != dn.end(); ++it)
        if (!(*it).name().isEmpty() && !(*it).value().isEmpty()) {
            result.push_back((*it).name().trimmed() + QLatin1Char('=') + dn_escape((*it).value().trimmed()));
        }
    return result.join(sep);
}

static QGpgME::DN::Attribute::List
reorder_dn(const QGpgME::DN::Attribute::List &dn, const QStringList &attrOrder)
{
    QGpgME::DN::Attribute::List unknownEntries;
    QGpgME::DN::Attribute::List result;
    unknownEntries.reserve(dn.size());
    result.reserve(dn.size());

    // find all unknown entries in their order of appearance
    for (QGpgME::DN::const_iterator it = dn.begin(); it != dn.end(); ++it)
        if (!attrOrder.contains((*it).name())) {
            unknownEntries.push_back(*it);
        }

    // process the known attrs in the desired order
    for (QStringList::const_iterator oit = attrOrder.begin(); oit != attrOrder.end(); ++oit)
        if (*oit == QLatin1String("_X_")) {
            // insert the unknown attrs
            std::copy(unknownEntries.begin(), unknownEntries.end(),
                      std::back_inserter(result));
            unknownEntries.clear(); // don't produce dup's
        } else {
            for (QGpgME::DN::const_iterator dnit = dn.begin(); dnit != dn.end(); ++dnit)
                if ((*dnit).name() == *oit) {
                    result.push_back(*dnit);
                }
        }

    return result;
}

//
//
// class DN
//
//

QGpgME::DN::DN()
{
    d = new Private();
    d->ref();
}

QGpgME::DN::DN(const QString &dn)
{
    d = new Private();
    d->ref();
    d->attributes = parse_dn(dn);
}

QGpgME::DN::DN(const char *utf8DN)
{
    d = new Private();
    d->ref();
    if (utf8DN) {
        d->attributes = parse_dn((const unsigned char *)utf8DN);
    }
}

QGpgME::DN::DN(const DN &other)
    : d(other.d)
{
    if (d) {
        d->ref();
    }
}

QGpgME::DN::~DN()
{
    if (d) {
        d->unref();
    }
}

const QGpgME::DN &QGpgME::DN::operator=(const DN &that)
{
    if (this->d == that.d) {
        return *this;
    }

    if (that.d) {
        that.d->ref();
    }
    if (this->d) {
        this->d->unref();
    }

    this->d = that.d;

    return *this;
}

QString QGpgME::DN::prettyDN() const
{
    if (!d) {
        return QString();
    }
    if (d->reorderedAttributes.empty()) {
        d->reorderedAttributes = reorder_dn(d->attributes, d->order);
    }
    return serialise(d->reorderedAttributes, QStringLiteral(","));
}

QString QGpgME::DN::dn() const
{
    return d ? serialise(d->attributes, QStringLiteral(",")) : QString();
}

QString QGpgME::DN::dn(const QString &sep) const
{
    return d ? serialise(d->attributes, sep) : QString();
}

// static
QString QGpgME::DN::escape(const QString &value)
{
    return dn_escape(value);
}

void QGpgME::DN::detach()
{
    if (!d) {
        d = new QGpgME::DN::Private();
        d->ref();
    } else if (d->refCount() > 1) {
        QGpgME::DN::Private *d_save = d;
        d = new QGpgME::DN::Private(*d);
        d->ref();
        d_save->unref();
    }
}

void QGpgME::DN::append(const Attribute &attr)
{
    detach();
    d->attributes.push_back(attr);
    d->reorderedAttributes.clear();
}

QString QGpgME::DN::operator[](const QString &attr) const
{
    if (!d) {
        return QString();
    }
    const QString attrUpper = attr.toUpper();
    for (QVector<Attribute>::const_iterator it = d->attributes.constBegin();
            it != d->attributes.constEnd(); ++it)
        if ((*it).name() == attrUpper) {
            return (*it).value();
        }
    return QString();
}

static QVector<QGpgME::DN::Attribute> empty;

QGpgME::DN::const_iterator QGpgME::DN::begin() const
{
    return d ? d->attributes.constBegin() : empty.constBegin();
}

QGpgME::DN::const_iterator QGpgME::DN::end() const
{
    return d ? d->attributes.constEnd() : empty.constEnd();
}

void QGpgME::DN::setAttributeOrder (const QStringList &order) const
{
    d->order = order;
}

const QStringList & QGpgME::DN::attributeOrder () const
{
    return d->order;
}
