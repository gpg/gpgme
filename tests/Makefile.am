## Process this file with automake to create Makefile.in

TESTS_ENVIRONMENT = GNUPGHOME=. 

TESTS = t-encrypt t-sign t-decrypt t-verify t-keylist

EXTRA_DIST = mkdemodirs pubdemo.asc secdemo.asc cipher-1.asc geheim.txt

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/intl

INCLUDES = 
LDADD = ../gpgme/libgpgme.la

noinst_PROGRAMS = $(TESTS)

distclean-local:
	$(srcdir)/mkdemodirs --clean

all-local: ./pubring.gpg ./secring.gpg

./pubring.gpg: $(srcdir)/pubdemo.asc
	-gpg --homedir . --import $(srcdir)/pubdemo.asc

./secring.gpg: ./Alpha/Secret.gpg 
	-gpg --homedir . --allow-secret-key-import --import Alpha/Secret.gpg Zulu/Secret.gpg

./Alpha/Secret.gpg: secdemo.asc 
	srcdir=$(srcdir) $(srcdir)/mkdemodirs 












