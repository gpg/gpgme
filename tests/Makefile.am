## Process this file with automake to create Makefile.in

TESTS = t-encrypt t-sign t-decrypt t-verify t-keylist

EXTRA_DIST = cipher-1.asc geheim.txt

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/intl

INCLUDES = 
LDADD = ../gpgme/libgpgme.la

noinst_PROGRAMS = $(TESTS)


