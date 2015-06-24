======
GPyGME
======

------------
Project Goal
------------

Intended as both a replacement of the older PyME bindings for Python 2 and Python 3, though it will only be implemented in Python 3.  Some effort may be made to allow it to work as a module or series of modules in Python 2, but there are no guarantees.

GPyGME is intended to be the official API for third party (i.e. non-C) languages and bindings.  While it should be able to be imported into any Python 3 code as a normal Python module or library, this is not the principal goal.  The real value is in providing an API for everyone by providing a pseudo-REST style API.  It is not actually a REST API because it is not purely web-based, though could be implemented that way (and almost certainly will be by many).

GPyGME will accept and respond with JSON data types to provide a method of interaction with GPGME with which most, if not all, modern application developers are familiar.  Consequently the bindings ought to be usable by anyone for any purpose for which GPGME could meet the need.

------------
Project Name
------------

GPyGME, with the first "G" being silent is pronounced the same way as `pygme <https://en.wikipedia.org/wiki/Pygmy_peoples>`_.  It could be thought of as a diminutive form of GPGME with the ability to unlock just as much power.

---------
Licensing
---------

GPyGME utilises the LGPL 2.1+ license, the same as GPGME itself.  As it is built on GPGME this is a requirement.  Documentation will be covered by both the GPLv3+ as with the GPGME documentation and a Creative Commons license.

Note that interacting with the GPyGME API as a stand alone interface (i.e. sending and receiving JSON data to it via a socket, command or other connection type) does not require conforming with either the GPL or LGPL licenses.  Only when importing or integrating this code into your own application does that become a requirement.

--------
Feedback
--------

GPyGME is written and maintained by `Ben McGinnes <mailto:ben@adversary.org>`_, but discussion ought to be conducted on the `gnupg-devel <https://lists.gnupg.org/mailman/listinfo/gnupg-devel>`_ mailing list.

