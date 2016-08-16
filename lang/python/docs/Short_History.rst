=======================
A Short History of PyME
=======================

In 2002 John Goerzen released PyME; Python bindings for the GPGME
module which utilised the current release of Python of the time
(Python 2.2 or 2.3) and SWIG.  Shortly after creating it and ensuring
it worked he stopped supporting it, though left his work available on
his Gopher site.

A couple of years later the project was picked up by Igor Belyi and
actively developed and maintained by him from 2004 to 2008.  Igor's
whereabouts at the time of this document's creation are unknown, but
the current authors do hope he is well.  We're assuming (or hoping)
that life did what life does and made continuing untenable.

In 2014 Martin Albrecht wanted to patch a bug in the PyME code and
discovered the absence of Igor.  Following a discussion on the PyME
mailing list he became the new maintainer for PyME, releasing version
0.9.0 in May of that year.  He remains the maintainer of the original
PyME release in Python 2.6 and 2.7 (available via PyPI).

In 2015 Ben McGinnes approached Martin about a Python 3 version, while
investigating how complex a task this would be the task ended up being
completed.  A subsequent discussion with Werner Koch led to the
decision to fold the Python 3 port back into the original GPGME
release in the languages subdirectory for non-C bindings.  Ben is the
maintainer of the Python 3 port within GPGME.

In 2016 Justus Winter updated a number of the Python 3 PyME SWIG
bindings during the course of GnuPG 2.1 development.  During the
course of this process the port was added to PyPI under the
alternative name of pyme3 (so as not to clash with the original
package for Python 2.6 and 2.7).


---------------------
The Annoyances of Git
---------------------

As anyone who has ever worked with git knows, submodules are a horrible
way to deal with pretty much anything.  In the interests of avoiding
migraines, that is being skipped with the addition of PyME to GPGME.
Instead the files will be added to the subdirectory, along with a copy
of the entire git log up to that point as a separate file within the
docs directory (old-commits.log).  As the log for PyME is nearly 100KB
and the log for GPGME is approximately 1MB, this would cause
considerable bloat, as well as some confusion, should the two be
merged.  Hence the unfortunate, but necessary, step to simply move the
files.  A regular repository version will be maintained should it be
possible to implement this better in the future.


------------------
The Perils of PyPI
------------------

This port is currently available in PyPI as pyme3 and uses the GPGME
version number from build time.  

Alternatively compiling GPGME and installing it from source will also
install the current version of PyME if Python 3 is detected.  If
multiple versions of Python 3 are installed then it will install in
the site-packages directory of the first installation located.

The version installed through either method can be checked like this:

::
   >>> from pyme import core
   >>> print(core.check_version())
   1.7.0-beta257
   >>>

Installing from PyPI should still result in the module being named
pyme when importing.
