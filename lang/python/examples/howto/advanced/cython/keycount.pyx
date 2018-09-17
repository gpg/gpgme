from __future__ import absolute_import

import cython
import gpg

c = gpg.Context()
seckeys = c.keylist(pattern=None, secret=True)
pubkeys = c.keylist(pattern=None, secret=False)

seclist = list(seckeys)
secnum = len(seclist)

publist = list(pubkeys)
pubnum = len(publist)

if cython.compiled is True:
    cc = "Powered by Cython compiled C code."
else:
    cc = "Powered by Python."

print("""
    Number of secret keys:  {0}
    Number of public keys:  {1}

  {2}
""".format(secnum, pubnum, cc))
