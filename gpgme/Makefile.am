# Process this file with automake to produce Makefile.in

EXTRA_DIST = gpgme-config.in gpgme.m4 mkerrors mkstatus
BUILT_SOURCES = errors.c status-table.h
bin_SCRIPTS = gpgme-config
m4datadir = $(datadir)/aclocal
m4data_DATA = gpgme.m4
include_HEADERS = gpgme.h
lib_LTLIBRARIES = libgpgme.la

libgpgme_la_LDFLAGS = -version-info \
      @LIBGPGME_LT_CURRENT@:@LIBGPGME_LT_REVISION@:@LIBGPGME_LT_AGE@
libgpgme_la_INCLUDES = -I$(top_srcdir)/lib 

libgpgme_la_SOURCES = \
	gpgme.h types.h util.h util.c \
	context.h ops.h \
	data.c recipient.c signers.c \
        wait.c wait.h \
	encrypt.c \
	decrypt.c \
	verify.c \
	sign.c \
        key.c key.h \
	keylist.c \
	trustlist.c \
	import.c \
        export.c \
	genkey.c \
	delete.c \
        rungpg.c rungpg.h status-table.h \
	syshdr.h io.h posix-io.c w32-io.c \
	gpgme.c version.c errors.c


errors.c : gpgme.h
	$(srcdir)/mkerrors < $(srcdir)/gpgme.h > errors.c

status-table.h : rungpg.h
	$(srcdir)/mkstatus < $(srcdir)/rungpg.h > status-table.h







