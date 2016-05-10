# $Id$

productname = 'pyme'
versionstr = "0.9.1"
revno = int('$Rev: 281 $'[6:-2])
revstr = "Rev %d" % revno
datestr = '$Date$'

versionlist = versionstr.split(".")
major = versionlist[0]
minor = versionlist[1]
patch = versionlist[2]
copyright = "Copyright (C) 2015 Ben McGinnes, 2014-2015 Martin Albrecht, 2004-2008 Igor Belyi, 2002 John Goerzen"
author = "Ben McGinnes"
author_email = "ben@adversary.org"
description = "Python 3 support for GPGME GnuPG cryptography library"
bigcopyright = """%(productname)s %(versionstr)s (%(revstr)s)
%(copyright)s <%(author_email)s>""" % locals()

banner = bigcopyright + """
This software comes with ABSOLUTELY NO WARRANTY; see the file
COPYING for details.  This is free software, and you are welcome
to distribute it under the conditions laid out in COPYING."""

homepage = "https://gnupg.org"
license = """Copyright (C) 2015 Ben McGinnes <ben@adversary.org>
Copyright (C) 2014, 2015 Martin Albrecht <martinralbrecht@googlemail.com>
Copyright (C) 2004, 2008 Igor Belyi <belyi@users.sourceforge.net>
Copyright (C) 2002 John Goerzen <jgoerzen@complete.org>

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA"""
