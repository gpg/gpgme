# build.mk - Makefile to build libgpg-error using Visual-C
# Copyright 2010 g10 Code GmbH
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

# This is a helper make script to build libgpg-error for WindowsCE
# using the Microsoft Visual C compiler.  

targetdir = /home/smb/xppro-gnu/src/gpgme/src
# The target build directory where we run the Visual C compiler/ This
# needs to be an absolute directory name.  Further we expect this
# structure of the tree:
# 
#   TARGET/src - Source directories:  One directory for each project
#         /bin - Installed DLLs
#         /lib - Installed import libs.
#         /include - Instaled header files.

targetdir = /home/smb/xppro-gnu
targetsrc = $(targetdir)/src

# Install directories (relative)
bindir = ../../../bin
libdir = ../../../lib
incdir = ../../../include


help:
	@echo "Run "
	@echo "  make -f ../contrib/conf-w32ce-msc/build.mk copy-source"
	@echo "on the POSIX system and then"
	@echo "  nmake -f build.mk all"
	@echo "  nmake -f build.mk install"
	@echo "on the Windows system"

ce_defines = -DWINCE -D_WIN32_WCE=0x502 -DUNDER_CE \
             -DWIN32_PLATFORM_PSPC -D_UNICODE -DUNICODE \
             -D_CONSOLE -DARM -D_ARM_
#-D_DEBUG -DDEBUG 

CFLAGS = -nologo -W3 -fp:fast -Os $(ce_defines) \
         -DHAVE_CONFIG_H -DDLL_EXPORT -D_CRT_SECURE_NO_WARNINGS \
	 -I. -I$(incdir) -I$(incdir)/gpg-extra

LDFLAGS =

# Standard source files
sources = \
	assuan-support.c    \
	ath-pth.c	    \
	ath-pthread.c	    \
	ath.c		    \
	ath.h		    \
	context.h	    \
	conversion.c	    \
	data-compat.c	    \
	data-fd.c	    \
	data-mem.c	    \
	data-stream.c	    \
	data-user.c	    \
	data.c		    \
	data.h		    \
	debug.c		    \
	debug.h		    \
	decrypt-verify.c    \
	decrypt.c	    \
	delete.c	    \
	dirinfo.c	    \
	edit.c		    \
	encrypt-sign.c	    \
	encrypt.c	    \
	engine-assuan.c	    \
	engine-backend.h    \
	engine-g13.c	    \
	engine-gpg.c	    \
	engine-gpgconf.c    \
	engine-gpgsm.c	    \
	engine-uiserver.c   \
	engine.c	    \
	engine.h	    \
	error.c		    \
	export.c	    \
	funopen.c	    \
	genkey.c	    \
	get-env.c	    \
	getauditlog.c	    \
	gpgconf.c	    \
	gpgme-tool.c	    \
	gpgme-w32spawn.c    \
	gpgme.c		    \
	import.c	    \
	isascii.c	    \
	kdpipeiodevice.h    \
	key.c		    \
	keylist.c	    \
	memrchr.c	    \
	op-support.c	    \
	opassuan.c	    \
	ops.h		    \
	passphrase.c	    \
	passwd.c	    \
	priv-io.h	    \
	progress.c	    \
	putc_unlocked.c	    \
	sema.h		    \
	setenv.c	    \
	sig-notation.c	    \
	sign.c		    \
	signers.c	    \
	stpcpy.c	    \
	trust-item.c	    \
	trustlist.c	    \
	ttyname_r.c	    \
	util.h		    \
	vasprintf.c	    \
	verify.c	    \
	version.c	    \
	vfs-create.c	    \
	vfs-mount.c	    \
	w32-ce.c	    \
	w32-ce.h	    \
	w32-glib-io.c	    \
	w32-io.c	    \
	w32-sema.c	    \
	w32-util.c	    \
	wait-global.c	    \
	wait-private.c	    \
	wait-user.c	    \
	wait.c		    \
	wait.h              \
	gpgme.def

# The object files we need to create from sources.
objs = \
	conversion.obj     \
	get-env.obj  	   \
	data.obj  	   \
	data-fd.obj  	   \
	data-stream.obj    \
	data-mem.obj  	   \
	data-user.obj  	   \
	data-compat.obj    \
	signers.obj  	   \
	sig-notation.obj   \
	wait.obj  	   \
	wait-global.obj    \
	wait-private.obj   \
	wait-user.obj  	   \
	op-support.obj     \
	encrypt.obj  	   \
	encrypt-sign.obj   \
	decrypt.obj  	   \
	decrypt-verify.obj \
	verify.obj  	   \
	sign.obj  	   \
	passphrase.obj 	   \
	progress.obj  	   \
	key.obj  	   \
	keylist.obj  	   \
	trust-item.obj 	   \
	trustlist.obj  	   \
	import.obj  	   \
	export.obj  	   \
	genkey.obj  	   \
	delete.obj  	   \
	edit.obj  	   \
	getauditlog.obj	   \
	opassuan.obj  	   \
	passwd.obj  	   \
	engine.obj  	   \
	engine-gpg.obj 	   \
	engine-gpgsm.obj     \
	assuan-support.obj   \
	engine-assuan.obj    \
	engine-gpgconf.obj   \
	engine-g13.obj 	   \
	vfs-mount.obj  	   \
	vfs-create.obj 	   \
	gpgconf.obj  	   \
	w32-ce.obj  	   \
	w32-util.obj  	   \
	w32-sema.obj  	   \
	w32-io.obj  	   \
	dirinfo.obj  	   \
	debug.obj  	   \
	gpgme.obj  	   \
	version.obj  	   \
	error.obj  	   \
	ath.obj  	   \
	vasprintf.obj  	   \
	ttyname_r.obj  	   \
	stpcpy.obj  	   \
	setenv.obj


# Sources files in this directory inclduing this Makefile
conf_sources = \
	build.mk \
	config.h

# Source files built by running the standard build system.
built_sources = \
	gpgme.h         \
	status-table.h


copy-static-source:
	@if [ ! -f ./gpgme.c ]; then \
           echo "Please cd to the src/ directory first"; \
	   exit 1; \
        fi
	cp -t $(targetsrc)/gpgme/src $(sources);
	cd ../contrib/conf-w32ce-msc ; \
            cp -t $(targetsrc)/gpgme/src $(conf_sources)

copy-built-source:
	@if [ ! -f ./gpgme.h ]; then \
           echo "Please build using ./autogen.sh --build-w32ce first"; \
	   exit 1; \
        fi
	cp -t $(targetsrc)/gpgme/src $(built_sources)
	echo '/* Dummy io.h header. */' > $(targetsrc)/gpgme/src/io.h

copy-source: copy-static-source copy-built-source 


.c.obj:
	$(CC) $(CFLAGS) -c $<

all:  $(sources) $(conf_sources) $(built_sources) $(objs)
	link    /DLL /IMPLIB:libgpgme-11-msc.lib \
                /OUT:libgpgme-11-msc.dll \
		/DEF:gpgme.def /NOLOGO /MANIFEST:NO \
		/NODEFAULTLIB:"oldnames.lib" /DYNAMICBASE:NO \
	        $(objs) \
		$(libdir)/libgpg-error-0-msc.lib \
		$(libdir)/libassuan-0-msc.lib \
		coredll.lib corelibc.lib ole32.lib oleaut32.lib uuid.lib \
		commctrl.lib /subsystem:windowsce,5.02

# Note that we don't need to create the install directories because
# libgpg-error must have been build and installed prior to this
# package.
install: all
	copy /y gpgme.h $(incdir:/=\)
	copy /y libgpgme-11-msc.dll $(bindir:/=\)
	copy /y libgpgme-11-msc.lib $(libdir:/=\)
