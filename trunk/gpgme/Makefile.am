# Process this file with automake to produce Makefile.in

EXTRA_DIST = gpgme-config.in  gpgme.m4
bin_SCRIPTS = gpgme-config
m4datadir = $(datadir)/aclocal
m4data_DATA = gpgme.m4
include_HEADERS = gpgme.h
lib_LTLIBRARIES = libgpgme.la

libgpgme_la_LDFLAGS = -version-info \
      @LIBGPGME_LT_CURRENT@:@LIBGPGME_LT_REVISION@:@LIBGPGME_LT_AGE@
libgpgme_la_INCLUDES = -I$(top_srcdir)/lib 

libgpgme_la_SOURCES = \
	gpgme.h \
	gpgme.c 



