.. _new-stuff:

What\'s New
===========

+-----------------------------------+-----------------------------------+
| Version:                          | 0.0.1-draft                       |
+-----------------------------------+-----------------------------------+
| GPGME Version:                    | 1.13.0                            |
+-----------------------------------+-----------------------------------+
| Author:                           | `Ben                              |
|                                   | McGinnes <https://gnupg.org/peopl |
|                                   | e/index.html#sec-1-5>`__          |
|                                   | <ben@gnupg.org>                   |
+-----------------------------------+-----------------------------------+
| Author GPG Key:                   | `DB4724E6FA4286C92B4E55C4321E4E23 |
|                                   | 73590E5D <https://hkps.pool.sks-k |
|                                   | eyservers.net/pks/lookup?search=0 |
|                                   | xDB4724E6FA4286C92B4E55C4321E4E23 |
|                                   | 73590E5D&exact=on&op=get>`__      |
+-----------------------------------+-----------------------------------+
| Language:                         | Australian English, British       |
|                                   | English                           |
+-----------------------------------+-----------------------------------+
| xml:lang:                         | en-AU, en-GB, en                  |
+-----------------------------------+-----------------------------------+

Last time the most obviously new thing was adding the *What\'s New*
section to the HOWTO. Now it\'s moving it out of the HOWTO.

.. _new-stuff-1-13-0:

New in GPGME 1·13·0
-------------------

Additions since GPGME 1.12.0 include:

-  Moving the *What\'s New* section out of the basic
   `HOWTO <gpgme-python-howto.org>`__ document and into its own file so
   as to more readily include other documents beyond that HOWTO.
-  Moving the preceding, archival, segments into `another
   file <what-was-new.org>`__.
-  Added ``gpg.version.versionintlist`` to make it easier for Python
   developers to check for a specific version number, even with beta
   versions (it will drop the \"-betaN\" part).
-  Bindings enter `maintenance mode <maintenance-mode>`__ from January,
   2019.
