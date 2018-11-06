.. _new-stuff:

What Was New
============

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
| Author GPG Key:                   | DB4724E6FA4286C92B4E55C4321E4E237 |
|                                   | 3590E5D                           |
+-----------------------------------+-----------------------------------+
| Language:                         | Australian English, British       |
|                                   | English                           |
+-----------------------------------+-----------------------------------+
| xml:lang:                         | en-AU, en-GB, en                  |
+-----------------------------------+-----------------------------------+

The following are all the past *What\'s New* sections for the Python
Bindings HOWTO and other documentation.

.. _gpgme-1-12-0:

What Was New in GPGME 1·12·0
----------------------------

The most obviously new point for those reading this guide is this
section on other new things, but that's hardly important. Not given all
the other things which spurred the need for adding this section and its
subsections.

.. _new-stuff-1-12-0:

New in GPGME 1·12·0
~~~~~~~~~~~~~~~~~~~

There have been quite a number of additions to GPGME and the Python
bindings to it since the last release of GPGME with versions 1.11.0 and
1.11.1 in April, 2018.

The bullet points of new additiions are:

-  an expanded section on
   `installing <gpgme-python-howto#installation>`__ and
   `troubleshooting <gpgme-python-howto#snafu>`__ the Python bindings.
-  The release of Python 3.7.0; which appears to be working just fine
   with our bindings, in spite of intermittent reports of problems for
   many other Python projects with that new release.
-  Python 3.7 has been moved to the head of the specified python
   versions list in the build process.
-  In order to fix some other issues, there are certain underlying
   functions which are more exposed through the
   `gpg.Context() <gpgme-python-howto#howto-get-context>`__, but ongoing
   documentation ought to clarify that or otherwise provide the best
   means of using the bindings. Some additions to ``gpg.core`` and the
   ``Context()``, however, were intended (see below).
-  Continuing work in identifying and confirming the cause of
   oft-reported `problems installing the Python bindings on
   Windows <gpgme-python-howto#snafu-runtime-not-funtime>`__.
-  GSOC: Google\'s Surreptitiously Ordered Conscription ... erm ... oh,
   right; Google\'s Summer of Code. Though there were two hopeful
   candidates this year; only one ended up involved with the GnuPG
   Project directly, the other concentrated on an unrelated third party
   project with closer ties to one of the GNU/Linux distributions than
   to the GnuPG Project. Thus the Python bindings benefited from GSOC
   participant Jacob Adams, who added the key\ :sub:`import` function;
   building on prior work by Tobias Mueller.
-  Several new methods functions were added to the gpg.Context(),
   including: `key\ import <gpgme-python-howto#howto-import-key>`__,
   `key\ export <gpgme-python-howto#howto-export-key>`__,
   `key\ exportminimal <gpgme-python-howto#howto-export-public-key>`__
   and
   `key\ exportsecret <gpgme-python-howto#howto-export-secret-key>`__.
-  Importing and exporting examples include versions integrated with
   Marcel Fest\'s recently released `HKP for
   Python <https://github.com/Selfnet/hkp4py>`__ module. Some
   `additional notes on this module <gpgme-python-howto#hkp4py>`__ are
   included at the end of the HOWTO.
-  Instructions for dealing with semi-walled garden implementations like
   ProtonMail are also included. This is intended to make things a
   little easier when communicating with users of ProtonMail\'s services
   and should not be construed as an endorsement of said service. The
   GnuPG Project neither favours, nor disfavours ProtonMail and the
   majority of this deals with interacting with the ProtonMail
   keyserver.
-  Semi-formalised the location where `draft
   versions <gpgme-python-howto#draft-editions>`__ of this HOWTO may
   periodically be accessible. This is both for the reference of others
   and testing the publishing of the document itself. Renamed this file
   at around the same time.
-  The Texinfo documentation build configuration has been replicated
   from the parent project in order to make to maintain consistency with
   that project (and actually ship with each release).
-  a reStructuredText (``.rst``) version is also generated for Python
   developers more used to and comfortable with that format as it is the
   standard Python documentation format and Python developers may wish
   to use it with Sphinx. Please note that there has been no testing of
   the reStructuredText version with Sphinx at all. The reST file was
   generated by the simple expedient of using
   `Pandoc <https://pandoc.org/>`__.
-  Added a new section for `advanced or experimental
   use <gpgme-python-howto#advanced-use>`__.
-  Began the advanced use cases with `a
   section <gpgme-python-howto#cython>`__ on using the module with
   `Cython <https://cython.org/>`__.
-  Added a number of new scripts to the ``example/howto/`` directory;
   some of which may be in advance of their planned sections of the
   HOWTO (and some are just there because it seemed like a good idea at
   the time).
-  Cleaned up a lot of things under the hood.
