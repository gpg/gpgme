.. _new-stuff:

What\'s New
===========

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
-  Added expanded detail on issues pertaining to installing for Windows
   users.
-  Bindings enter `maintenance mode <maintenance-mode>`__ from January,
   2019.
-  Added documentation on maintenance mode and what changes can be made
   to the code when in that status. Essentially that boils down to bug
   fixes only and no feature requests.
-  The import-keys-hkp.py example script, which uses the ``hkp4py``
   module to search the SKS servers for a key, has been tightened up to
   search for both hexadecimal key IDs and user ID strings with reduced
   chance of unnecessary repitition. There may still be some repetition
   if a key includes a user ID matching the hexadecimal value of a key
   ID.
