.. _maintenance-mode:

Maintenance Mode from 2019
==========================

+-----------------+------------------------------------------+
| Version:        | 0.0.1                                    |
+-----------------+------------------------------------------+
| GPGME Version:  | 1.13.0                                   |
+-----------------+------------------------------------------+
| Author:         | Ben McGinnes <ben@gnupg.org>             |
+-----------------+------------------------------------------+
| Author GPG Key: | DB4724E6FA4286C92B4E55C4321E4E2373590E5D |
+-----------------+------------------------------------------+
| Language:       | Australian English, British English      |
+-----------------+------------------------------------------+
| xml:lang:       | en-AU, en-GB, en                         |
+-----------------+------------------------------------------+

From the beginning of 2019 the Python bindings to GPGME will enter
maintenance mode, meaning that new features will not be added and only
bug fixes and security fixes will be made. This also means that
documentation beyond that existing at the end of 2018 will not be
developed further except to correct errors.

Though use of these bindings appears to have been quite well received,
there has been no indication of what demand there is, if any for either
financial backing of the current Python bindings development or support
contracts with g10code GmbH citing the necessity of including the
bindings.

.. _maintenance-mode-bm:

Maintainer from 2019 onward
---------------------------

How does this affect the position of GnuPG Python Bindings Maintainer?

Well, I will remain as maintainer of the bindings; but without funding
for that position, the amount of time I will be able to dedicate solely
to this task will be limited and reduced to volunteered time. As with
all volunteered time and effort in free software projects, this will be
subject to numerous external imperatives.

.. _maintenance-mode-blade-runner:

Using the Python Bindings from 2019 and beyond
----------------------------------------------

For most, if not all, Python developers using these bindings; they will
continue to "just work" the same as they always have. Expansions of
GPGME itself are usually handled by SWIG with the existing code and thus
bindings are generated properly when the bindings are installed
alongside GPGME and when the latter is built from source.

In the rare circumstances where that is not enough to address some new
addition to GPGME, then that is a bug and thus subject to the
maintenance mode provisions (i.e. it will be fixed following a bug
report being raised and your humble author will need to remember where
the timesheet template was filed, depending on how many years off such
an event is).

All the GPGME functionality will continue to be accessible via the lower
level, dynamically generated methods which match the GPGME C
documentation. While the more intuitively Pythonic higher level layer
already covers the vast majority of functionality people require with
key generation, signatures, certifications (key signing), encryption,
decryption, verification, validation, trust levels and so on.

Any wanted features lacking in the Python bindings are usually lacking
because they are missing from GPGME itself (e.g. revoking keys via the
API) and in such cases they are usually deliberately excluded. More
discussion of these issues can be found in the archives of the
`gnupg-devel mailing
list <https://lists.gnupg.org/mailman/listinfo/gnupg-devel>`__.

Any features existing in the dynamically generated layer for which
people want a specific, higher level function included to make it more
Pythonic (e.g. to avoid needing to learn or memorise cryptographic mode
values or GnuPG status code numbers), would be a feature request and
*not* a bug.

It is still worthwhile requesting it, but the addition of such a feature
would not be guaranteed and provided on a purely volunteer basis.
Expediting such a request would require funding that request.

Those with a commercial interest in expediting such a feature request
already know how to `expedite
it <https://gnupg.org/cgi-bin/procdonate.cgi?mode=preset>`__ (use the
message field to state what feature is being requested).
