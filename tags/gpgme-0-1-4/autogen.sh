#!/bin/sh
# Run this to generate all the initial makefiles, etc.
# It is only needed for the CVS version.

PGM=GPGME
DIE=no

#
# Use --build-w32 to prepare the cross compiling build for Windoze
#
if test "$1" = "--build-w32"; then
    shift
    target=i386--mingw32
    host=`./config.guess`
        
    CC="${target}-gcc"
    CPP="${target}-gcc -E"
    RANLIB="${target}-ranlib"
        
    cc_version=`$CC --version`
    if ! echo "$cc_version" | egrep '[0-9]+wk[0-9]+' ; then
        echo "gcc version $cc_version is not supported" >&2
        echo "see doc/README.W32 for instructions" >&2
        exit 1
    fi
        
    if [ -f config.h ]; then
        if grep HAVE_DOSISH_SYSTEM config.h | grep undef >/dev/null; then
            echo "Pease run a 'make distclean' first" >&2
            exit 1
        fi
    fi

    export CC CPP RANLIB
    ./configure --host=${host} --target=${target} $*
    exit $?
fi


autoconf_vers=2.13
automake_vers=1.4
aclocal_vers=1.4
libtool_vers=1.3

if (autoconf --version) < /dev/null > /dev/null 2>&1 ; then
    if (autoconf --version | awk 'NR==1 { if( $3 >= '$autoconf_vers') \
			       exit 1; exit 0; }');
    then
       echo "**Error**: "\`autoconf\'" is too old."
       echo '           (version ' $autoconf_vers ' or newer is required)'
       DIE="yes"
    fi
else
    echo
    echo "**Error**: You must have "\`autoconf\'" installed to compile $PGM."
    echo '           (version ' $autoconf_vers ' or newer is required)'
    DIE="yes"
fi

if (automake --version) < /dev/null > /dev/null 2>&1 ; then
  if (automake --version | awk 'NR==1 { if( $4 >= '$automake_vers') \
			     exit 1; exit 0; }');
     then
     echo "**Error**: "\`automake\'" is too old."
     echo '           (version ' $automake_vers ' or newer is required)'
     DIE="yes"
  fi
  if (aclocal --version) < /dev/null > /dev/null 2>&1; then
    if (aclocal --version | awk 'NR==1 { if( $4 >= '$aclocal_vers' ) \
						exit 1; exit 0; }' );
    then
      echo "**Error**: "\`aclocal\'" is too old."
      echo '           (version ' $aclocal_vers ' or newer is required)'
      DIE="yes"
    fi
  else
    echo
    echo "**Error**: Missing "\`aclocal\'".  The version of "\`automake\'
    echo "           installed doesn't appear recent enough."
    DIE="yes"
  fi
else
    echo
    echo "**Error**: You must have "\`automake\'" installed to compile $PGM."
    echo '           (version ' $automake_vers ' or newer is required)'
    DIE="yes"
fi


if (libtool --version) < /dev/null > /dev/null 2>&1 ; then
    if (libtool --version | awk 'NR==1 { if( $4 >= '$libtool_vers') \
			       exit 1; exit 0; }');
    then
       echo "**Error**: "\`libtool\'" is too old."
       echo '           (version ' $libtool_vers ' or newer is required)'
       DIE="yes"
    fi
else
    echo
    echo "**Error**: You must have "\`libtool\'" installed to compile $PGM."
    echo '           (version ' $libtool_vers ' or newer is required)'
    DIE="yes"
fi

if test "$DIE" = "yes"; then
    exit 1
fi

echo "Running libtoolize...  Ignore non-fatal messages."
echo "no" | libtoolize


echo "Running aclocal..."
aclocal
echo "Running autoheader..."
autoheader
echo "Running automake --gnu ..."
automake --gnu;
echo "Running autoconf..."
autoconf

if test "$*" = ""; then
    conf_options="--enable-maintainer-mode"
else
   conf_options=$*
fi
echo "Running ./configure $conf_options"
./configure $conf_options




