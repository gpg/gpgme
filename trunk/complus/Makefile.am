## Process this file with automake to produce Makefile.in

EXTRA_DIST = WINE-LICENSE WINE-AUTHORS

# No need to install this becuase we are cross-compiling anyway.
noinst_PROGRAMS = gpgcom

INCLUDES = -I$(top_srcdir)/jnlib
LDADD = -L ../jnlib -ljnlib 

comheaders = obj_base.h basetsd.h guiddef.h  wtypes.h

gpgcom_SOURCES = main.c main.h \
		$(comheaders) \
		ignupg.c ignupg.h 


