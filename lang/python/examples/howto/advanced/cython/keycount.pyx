import gpg

c = gpg.Context()
seckeys = c.keylist(pattern=None, secret=True)
pubkeys = c.keylist(pattern=None, secret=False)

seclist = list(seckeys)
secnum = len(seclist)

publist = list(pubkeys)
pubnum = len(publist)

print("""
Number of secret keys:  {0}
Number of public keys:  {1}
""".format(secnum, pubnum))
