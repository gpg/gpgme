/* gpgcom.c - COM+ component to access GnuPG
 *	Copyright (C) 2001 g10 Code GmbH
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <windows.h>

#include <ole2.h>

#include "argparse.h"

#include "main.h"
#include "igpgme.h"

static void register_server (void);
static void unregister_server (void);
static void enter_complus (void);


enum cmd_and_opt_values { aNull = 0,
    oQuiet	  = 'q',
    oVerbose	  = 'v',

    oNoVerbose = 500,
    oOptions,
    oDebug,
    oDebugAll,
    oNoGreeting,
    oNoOptions,
    oHomedir,
    oGPGBinary,
    oRegServer,
    oUnregServer,
    oEmbedding,
aTest };


static ARGPARSE_OPTS opts[] = {

    { 301, NULL, 0, N_("@Options:\n ") },

    { oVerbose, "verbose",   0, N_("verbose") },
    { oQuiet,	"quiet",     0, N_("be somewhat more quiet") },
    { oOptions, "options"  , 2, N_("read options from file")},
    { oDebug,	"debug"     ,4|16, N_("set debugging flags")},
    { oDebugAll, "debug-all" ,0, N_("enable full debugging")},
    { oGPGBinary, "gpg-program", 2 , "" },
    { oRegServer, "RegServer" , 0, "" },
    { oUnregServer, "UnregServer" , 0, "" },
    { oEmbedding, "Embedding" , 0, "" },
{0} };




static const char *
my_strusage( int level )
{
    const char *p;
    switch( level ) {
      case 11: p = "gpgcom";
	break;
      case 13: p = VERSION; break;
      /*case 17: p = PRINTABLE_OS_NAME; break;*/
      case 19: p =
	    _("Please report bugs to <gpgme-bugs@gnupg.org>.\n");
	break;
      case 1:
      case 40:	p =
	    _("Usage: gpgcom [options] (-h for help)");
	break;
      case 41:	p =
	    _("Syntax: gpgcom [options]\n"
	      "GnuPG COM+ component\n");
	break;

      default:	p = NULL;
    }
    return p;
}


int
main (int argc, char **argv )
{
    ARGPARSE_ARGS pargs;
    int orig_argc;
    char **orig_argv;
    FILE *configfp = NULL;
    char *configname = NULL;
    unsigned configlineno;
    int parse_debug = 0;
    int default_config =1;
    int greeting = 0;
    int nogreeting = 0;
    int action = 0;

    set_strusage( my_strusage );
    /*log_set_name ("gpa"); not yet implemented in logging.c */

    opt.homedir = getenv("GNUPGHOME");
    if( !opt.homedir || !*opt.homedir ) {
      #ifdef HAVE_DOSISH_SYSTEM
	opt.homedir = "c:/gnupg";
      #else
	opt.homedir = "~/.gnupg";
      #endif
    }

    /* check whether we have a config file on the commandline */
    orig_argc = argc;
    orig_argv = argv;
    pargs.argc = &argc;
    pargs.argv = &argv;
    pargs.flags= 1|(1<<6);  /* do not remove the args, ignore version */
    while( arg_parse( &pargs, opts) ) {
	if( pargs.r_opt == oDebug || pargs.r_opt == oDebugAll )
	    parse_debug++;
	else if( pargs.r_opt == oOptions ) {
	    /* yes there is one, so we do not try the default one, but
	     * read the option file when it is encountered at the commandline
	     */
	    default_config = 0;
	}
	else if( pargs.r_opt == oNoOptions )
	    default_config = 0; /* --no-options */
	else if( pargs.r_opt == oHomedir )
	    opt.homedir = pargs.r.ret_str;
    }

    if( default_config )
	configname = make_filename(opt.homedir, "gpgme.conf", NULL );


    argc = orig_argc;
    argv = orig_argv;
    pargs.argc = &argc;
    pargs.argv = &argv;
    pargs.flags=  1 | (1<<5);  /* do not remove the args, allow one dash */
  next_pass:
    if( configname ) {
	configlineno = 0;
	configfp = fopen( configname, "r" );
	if( !configfp ) {
	    if( default_config ) {
		if( parse_debug )
		    log_info(_("NOTE: no default option file `%s'\n"),
							    configname );
	    }
	    else {
		log_error(_("option file `%s': %s\n"),
				    configname, strerror(errno) );
		exit(2);
	    }
	    free(configname); configname = NULL;
	}
	if( parse_debug && configname )
	    log_info(_("reading options from `%s'\n"), configname );
	default_config = 0;
    }

    while( optfile_parse( configfp, configname, &configlineno,
						&pargs, opts) ) {
	switch( pargs.r_opt ) {
	  case oQuiet: opt.quiet = 1; break;
	  case oVerbose: opt.verbose++; break;

	  case oDebug: opt.debug |= pargs.r.ret_ulong; break;
	  case oDebugAll: opt.debug = ~0; break;

	  case oOptions:
	    /* config files may not be nested (silently ignore them) */
	    if( !configfp ) {
		free(configname);
		configname = xstrdup(pargs.r.ret_str);
		goto next_pass;
	    }
	    break;
	  case oNoGreeting: nogreeting = 1; break;
	  case oNoVerbose: opt.verbose = 0; break;
	  case oNoOptions: break; /* no-options */
	  case oHomedir: opt.homedir = pargs.r.ret_str; break;
	  case oGPGBinary:  break;

          case oRegServer: action = 1; break;
          case oUnregServer: action = 2; break;
          case oEmbedding: action = 3; break;

	  default : pargs.err = configfp? 1:2; break;
	}
    }
    if( configfp ) {
	fclose( configfp );
	configfp = NULL;
	free(configname); configname = NULL;
	goto next_pass;
    }
    free( configname ); configname = NULL;
    if( log_get_errorcount(0) )
	exit(2);
    if( nogreeting )
	greeting = 0;

    if( greeting ) {
	fprintf(stderr, "%s %s; %s\n",
			strusage(11), strusage(13), strusage(14) );
	fprintf(stderr, "%s\n", strusage(15) );
    }
  #ifdef IS_DEVELOPMENT_VERSION
    log_info("NOTE: this is a development version!\n");
  #endif

    if ( action == 1 )
        register_server ();
    else if (action == 2 )
        unregister_server ();
    else if (action == 3 )
        enter_complus ();
    else {
        fprintf (stderr, "This is a COM+ component with no user interface.\n"
                 "gpgme --help will give you a list of options\n" );
        exit (1);
    }

    return 0;
}


static void
register_progid ( const char *name )
{
    HKEY hk = 0;
    char buf[500];

    /* Create a ProgID entry to point to the ClassID */
    sprintf (buf, "%.400s", name);
    if (RegCreateKeyA (HKEY_CLASSES_ROOT, buf, &hk)) {
        fprintf (stderr,"RegCreateKey(`%s') failed\n", buf);
        exit (1);
    }
    sprintf (buf, "g10 Code's GnuPG made easy COMponent" );
    if (RegSetValueExA (hk, 0, 0, REG_SZ, buf, 0)) {
        fprintf (stderr,"RegSetValueEx(`%s') failed\n", buf);
        exit (1);
    }
    if (RegCloseKey (hk)) {
        fprintf (stderr,"RegCloseKey() failed\n");
        exit (1);
    }
    sprintf (buf, "%.400s\\CLSID", name);
    if (RegCreateKeyA (HKEY_CLASSES_ROOT, buf, &hk)) {
        fprintf (stderr,"RegCreateKey(`%s') failed\n", buf);
        exit (1);
    }
    sprintf (buf, "%.100s", debugstr_guid (&CLSID_Gpgme) );
    if (RegSetValueExA (hk, 0, 0, REG_SZ, buf, strlen (buf))) {
        fprintf (stderr,"RegSetValueEx(`%s') failed\n", buf);
        exit (1);
    }
    if (RegCloseKey (hk)) {
        fprintf (stderr,"RegCloseKey() failed\n");
        exit (1);
    }
    hk = 0;
}


static void
register_typelib (void)
{
    ITypeLib  *pTypeLib;
    HRESULT hr;
    char name[500];
    wchar_t *wname;
    size_t n;

    if ( !GetModuleFileNameA (0, name, sizeof (name)-10) ) {
        fprintf (stderr,"GetModuleFileName() failed: %d\n",
                 (int)GetLastError());
        exit (1);
    }
    n = mbstowcs (NULL, name, strlen(name)+1);
    wname = xmalloc ((n+1)*sizeof *wname);
    mbstowcs (wname, name, strlen (name)+1);

    hr = CoInitializeEx (NULL, COINIT_APARTMENTTHREADED); 
    if (hr)
        fprintf (stderr, "CoInitializeEx() failed: hr=%lu\n", hr);

    hr = LoadTypeLibEx (wname, REGKIND_REGISTER, &pTypeLib);
    if (hr)
        fprintf (stderr, "LoadTypeLibEx() failed: hr=%lx\n", hr);

    ITypeLib_Release (pTypeLib);
    CoUninitialize ();
    free (wname);
}

static void
unregister_typelib (void)
{
    UnRegisterTypeLib (&TLBID_Gpgcom, 1, 0, LANG_NEUTRAL, SYS_WIN32);
}

static void
register_server ()
{
    HKEY hk = 0;
    char buf[500];


    register_typelib ();

    /* Create a key for the CLSID */
    sprintf (buf, "CLSID\\%.100s", debugstr_guid (&CLSID_Gpgme) );
    if (RegCreateKeyA (HKEY_CLASSES_ROOT, buf, &hk)) {
        fprintf (stderr,"RegCreateKey(`%s') failed\n", buf);
        exit (1);
    }
    /* Store our class name as default value */
    strcpy (buf, "Gpgme");
    if (RegSetValueExA (hk, 0, 0, REG_SZ, buf, strlen (buf))) {
        fprintf (stderr,"RegSetValueEx(`%s') failed\n", buf);
        exit (1);
    }
    
    /* Set the application ID */
    sprintf (buf, "%.100s", debugstr_guid (&APPID_Gpgcom) );
    if (RegSetValueExA (hk, "AppID", 0, REG_SZ, buf, strlen (buf))) {
        fprintf (stderr,"RegSetValueEx(`%s') failed\n", buf);
        exit (1);
    }
    if (RegCloseKey (hk)) {
        fprintf (stderr,"RegCloseKey() failed\n");
        exit (1);
    }
    hk = 0;
    
    /* Create the LocalServer32 subkey under the CLSID key */
    sprintf (buf, "CLSID\\%.100s\\LocalServer32",
             debugstr_guid (&CLSID_Gpgme) );
    if (RegCreateKeyA (HKEY_CLASSES_ROOT, buf, &hk)) {
        fprintf (stderr,"RegCreateKey(`%s') failed\n", buf);
        exit (1);
    }
    /* retrieve the module name and add it under the key */
    if ( !GetModuleFileNameA (0, buf, sizeof (buf)-10) ) {
        fprintf (stderr,"GetModuleFileName() failed\n");
        exit (1);
    }
    if (RegSetValueExA (hk, 0, 0, REG_SZ, buf, strlen (buf))) {
        fprintf (stderr,"RegSetValueEx(`%s') failed\n", buf);
        exit (1);
    }
    if (RegCloseKey (hk)) {
        fprintf (stderr,"RegCloseKey() failed\n");
        exit (1);
    }
    hk = 0;

    /* Create the ProgID subkey under the CLSID key */
    sprintf (buf, "CLSID\\%.100s\\ProgID",
             debugstr_guid (&CLSID_Gpgme) );
    if (RegCreateKeyA (HKEY_CLASSES_ROOT, buf, &hk)) {
        fprintf (stderr,"RegCreateKey(`%s') failed\n", buf);
        exit (1);
    }
    if (RegSetValueExA (hk, 0, 0, REG_SZ, "Gpgcom.Gpgme.1", 0)) {
        fprintf (stderr,"RegSetValueEx(`%s') failed\n", buf);
        exit (1);
    }
    if (RegCloseKey (hk)) {
        fprintf (stderr,"RegCloseKey() failed\n");
        exit (1);
    }
    hk = 0;
    /* Create the VersionIndependentProgID subkey under the CLSID key */
    sprintf (buf, "CLSID\\%.100s\\VersionIndependentProgID",
             debugstr_guid (&CLSID_Gpgme) );
    if (RegCreateKeyA (HKEY_CLASSES_ROOT, buf, &hk)) {
        fprintf (stderr,"RegCreateKey(`%s') failed\n", buf);
        exit (1);
    }
    if (RegSetValueExA (hk, 0, 0, REG_SZ, "Gpgcom.Gpgme", 0)) {
        fprintf (stderr,"RegSetValueEx(`%s') failed\n", buf);
        exit (1);
    }
    if (RegCloseKey (hk)) {
        fprintf (stderr,"RegCloseKey() failed\n");
        exit (1);
    }
    hk = 0;

    
    /* Create a key to store AppID info */
    sprintf (buf, "AppID\\%.100s",  debugstr_guid (&APPID_Gpgcom) );
    if (RegCreateKeyA (HKEY_CLASSES_ROOT, buf, &hk)) {
        fprintf (stderr,"RegCreateKey(`%s') failed\n", buf);
        exit (1);
    }
    /* Store the name as default value */
    strcpy (buf, "Gpgcom");
    if (RegSetValueExA (hk, 0, 0, REG_SZ, buf, strlen (buf))) {
        fprintf (stderr,"RegSetValueEx(`%s') failed\n", buf);
        exit (1);
    }
    if (RegCloseKey (hk)) {
        fprintf (stderr,"RegCloseKey() failed\n");
        exit (1);
    }
    hk = 0;

    register_progid ("Gpgcom.Gpgme");
    register_progid ("Gpgcom.Gpgme.1");

    /* Create a convenience cross reference to the AppID */
    sprintf (buf, "AppID\\gpgcom.exe");
    if (RegCreateKeyA (HKEY_CLASSES_ROOT, buf, &hk)) {
        fprintf (stderr,"RegCreateKey(`%s') failed\n", buf);
        exit (1);
    }
    sprintf (buf, "%.100s", debugstr_guid (&APPID_Gpgcom) );
    if (RegSetValueExA (hk, "AppID", 0, REG_SZ, buf, strlen (buf))) {
        fprintf (stderr,"RegSetValueEx(`%s') failed\n", buf);
        exit (1);
    }
    if (RegCloseKey (hk)) {
        fprintf (stderr,"RegCloseKey() failed\n");
        exit (1);
    }
    hk = 0;

    fprintf (stderr,"*** Component registered\n");
}

static void
unregister_server ()
{
    char buf[500];

    unregister_typelib ();
    sprintf (buf, "CLSID\\%.100s\\LocalServer32",
             debugstr_guid (&CLSID_Gpgme) );
    if (RegDeleteKey (HKEY_CLASSES_ROOT, buf))
        fprintf (stderr,"RegDeleteKey(`%s') failed\n", buf);

    sprintf (buf, "CLSID\\%.100s\\ProgID",  debugstr_guid (&CLSID_Gpgme) );
    if (RegDeleteKey (HKEY_CLASSES_ROOT, buf))
        fprintf (stderr,"RegDeleteKey(`%s') failed\n", buf);

    sprintf (buf, "CLSID\\%.100s", debugstr_guid (&CLSID_Gpgme) );
    if (RegDeleteKey (HKEY_CLASSES_ROOT, buf))
        fprintf (stderr,"RegDeleteKey(`%s') failed\n", buf);

    sprintf (buf, "Gpgcom.Gpgme.1\\CLSID");
    if (RegDeleteKey (HKEY_CLASSES_ROOT, buf))
        fprintf (stderr,"RegDeleteKey(`%s') failed\n", buf);
    sprintf (buf, "Gpgcom.Gpgme.1");
    if (RegDeleteKey (HKEY_CLASSES_ROOT, buf))
        fprintf (stderr,"RegDeleteKey(`%s') failed\n", buf);

    sprintf (buf, "Gpgcom.Gpgme\\CLSID");
    if (RegDeleteKey (HKEY_CLASSES_ROOT, buf))
        fprintf (stderr,"RegDeleteKey(`%s') failed\n", buf);
    sprintf (buf, "Gpgcom.Gpgme");
    if (RegDeleteKey (HKEY_CLASSES_ROOT, buf))
        fprintf (stderr,"RegDeleteKey(`%s') failed\n", buf);


    sprintf (buf, "AppID\\%.100s", debugstr_guid (&APPID_Gpgcom) );
    if (RegDeleteKey (HKEY_CLASSES_ROOT, buf))
        fprintf (stderr,"RegDeleteKey(`%s') failed\n", buf);

    sprintf (buf, "AppID\\gpgcom.exe" );
    if (RegDeleteKey (HKEY_CLASSES_ROOT, buf))
        fprintf (stderr,"RegDeleteKey(`%s') failed\n", buf);

    fprintf (stderr,"*** component unregistered\n");
}


static void
enter_complus ()
{
    HANDLE running;
    DWORD reg;
    IClassFactory *factory;
    CLSID clsid;
    HRESULT hr;

    fprintf (stderr,"*** enter enter_complus()\n");
    CoInitializeEx (NULL, COINIT_MULTITHREADED); 
    running = CreateEvent (NULL, FALSE, FALSE, NULL );
    fprintf (stderr,"*** CoInitialize() done; event=%lx\n", (unsigned long)running );

    igpgme_register_exit_event (running);
    factory = igpgme_factory_new ( &clsid ); 
    fprintf (stderr,"*** igpgme_factory_new() done; got=%p\n", factory );
    hr = CoRegisterClassObject (&clsid, (IUnknown*)factory, 
                           CLSCTX_LOCAL_SERVER,
                           REGCLS_SUSPENDED|REGCLS_MULTIPLEUSE, &reg );
    if (hr) {
        fprintf (stderr, "CoRegisterClassObject() failed: hr=%lx\n", hr);
        exit (1);
    }
    hr = CoResumeClassObjects ();
    if (hr) 
        fprintf (stderr, "CoRegisterClassObject() failed: hr=%lx\n", hr);
    fprintf (stderr,"*** class object registered; waiting\n" );

    WaitForSingleObject ( running, INFINITE );
    fprintf (stderr,"*** shutting down\n" );
    igpgme_register_exit_event (NULL);
    CloseHandle (running);
    CoRevokeClassObject ( reg );
    fprintf (stderr,"*** class object revoked\n" );
    igpgme_factory_release (factory);
    fprintf (stderr,"*** factory released\n" );
    CoUninitialize (); 
    fprintf (stderr,"*** leave enter_complus()\n" );
}

