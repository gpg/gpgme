# Copyright (C) 2004 Igor Belyi <belyi@users.sourceforge.net>
# Copyright (C) 2002 John Goerzen <jgoerzen@complete.org>
#
#    This library is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Lesser General Public
#    License as published by the Free Software Foundation; either
#    version 2.1 of the License, or (at your option) any later version.
#
#    This library is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this library; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA

from __future__ import absolute_import, print_function, unicode_literals

from getpass import getpass

del absolute_import, print_function, unicode_literals


def passphrase_stdin(hint, desc, prev_bad, hook=None):
    """This is a sample callback that will read a passphrase from
    the terminal.  The hook here, if present, will be used to describe
    why the passphrase is needed."""
    why = ''
    if hook is not None:
        why = ' ' + hook
    if prev_bad:
        why += ' (again)'
    print("Please supply %s' password%s:" % (hint, why))
    return getpass()


def progress_stdout(what, type, current, total, hook=None):
    print("PROGRESS UPDATE: what = %s, type = %d, current = %d, total = %d" %
          (what, type, current, total))


def readcb_fh(count, hook):
    """A callback for data.  hook should be a Python file-like object."""
    if count:
        # Should return '' on EOF
        return hook.read(count)
    else:
        # Wants to rewind.
        if not hasattr(hook, 'seek'):
            return None
        hook.seek(0, 0)
        return None
