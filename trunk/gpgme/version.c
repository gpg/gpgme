/* version.c -  version check
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *      Copyright (C) 2001 g10 Code GmbH
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
#include <ctype.h>

#include "gpgme.h"
#include "context.h"
#include "rungpg.h"
#include "sema.h"
#include "util.h"
#include "key.h" /* for key_cache_init */

static int lineno;
static char *tmp_engine_version;

static const char *get_engine_info (void);


static void
do_subsystem_inits (void)
{
    static int done = 0;

    if (done)
        return;
    _gpgme_sema_subsystem_init ();
    _gpgme_key_cache_init ();
}



static const char*
parse_version_number ( const char *s, int *number )
{
    int val = 0;

    if ( *s == '0' && isdigit(s[1]) )
	return NULL; /* leading zeros are not allowed */
    for ( ; isdigit(*s); s++ ) {
	val *= 10;
	val += *s - '0';
    }
    *number = val;
    return val < 0? NULL : s;
}


static const char *
parse_version_string( const char *s, int *major, int *minor, int *micro )
{
    s = parse_version_number ( s, major );
    if ( !s || *s != '.' )
	return NULL;
    s++;
    s = parse_version_number ( s, minor );
    if ( !s || *s != '.' )
	return NULL;
    s++;
    s = parse_version_number ( s, micro );
    if ( !s )
	return NULL;
    return s; /* patchlevel */
}

static const char *
compare_versions ( const char *my_version, const char *req_version )
{
    int my_major, my_minor, my_micro;
    int rq_major, rq_minor, rq_micro;
    const char *my_plvl, *rq_plvl;

    if ( !req_version )
	return my_version;

    my_plvl = parse_version_string ( my_version,
                                     &my_major, &my_minor, &my_micro );
    if ( !my_plvl )
	return NULL;  /* very strange: our own version is bogus */
    rq_plvl = parse_version_string( req_version,
                                    &rq_major, &rq_minor, &rq_micro );
    if ( !rq_plvl )
	return NULL;  /* req version string is invalid */

    if ( my_major > rq_major
         || (my_major == rq_major && my_minor > rq_minor)
         || (my_major == rq_major && my_minor == rq_minor 
             && my_micro > rq_micro)
         || (my_major == rq_major && my_minor == rq_minor
             && my_micro == rq_micro
             && strcmp( my_plvl, rq_plvl ) >= 0) ) {
	return my_version;
    }
    return NULL;
}


/**
 * gpgme_check_version:
 * @req_version: A string with a version
 * 
 * Check that the the version of the library is at minimum the requested one
 * and return the version string; return NULL if the condition is not
 * met.  If a NULL is passed to this function, no check is done and
 * the version string is simply returned.  It is a pretty good idea to
 * run this function as soon as possible, because it also intializes 
 * some subsystems.  In a multithreaded environment if should be called
 * before the first thread is created.
 * 
 * Return value: The version string or NULL
 **/
const char *
gpgme_check_version ( const char *req_version )
{
    do_subsystem_inits ();
    return compare_versions ( VERSION, req_version );
}


/**
 * gpgme_get_engine_info:
 *  
 * Return information about the underlying crypto engine.  This is an
 * XML string with various information.  To get the version of the
 * crypto engine it should be sufficient to grep for the first
 * <literal>version</literal> tag and use it's content.  A string is
 * always returned even if the crypto engine is not installed; in this
 * case a XML string with some error information is returned.
 * 
 * Return value: A XML string with information about the crypto engine.
 **/
const char *
gpgme_get_engine_info ()
{
    do_subsystem_inits ();
    return get_engine_info ();
}

/**
 * gpgme_check_engine:
 * 
 * Check whether the installed crypto engine matches the requirement of
 * GPGME.
 *
 * Return value: 0 or an error code.
 **/
GpgmeError
gpgme_check_engine ()
{
    const char *info = gpgme_get_engine_info ();
    const char *s, *s2;

    s = strstr (info, "<version>");
    if (s) {
        s += 9;
        s2 = strchr (s, '<');
        if (s2) {
            char *ver = xtrymalloc (s2 - s + 1);
            if (!ver)
                return mk_error (Out_Of_Core);
            memcpy (ver, s, s2-s);
            ver[s2-s] = 0;
            s = compare_versions ( ver, NEED_GPG_VERSION );
            xfree (ver);
            if (s)
                return 0;
        }
    }
    return mk_error (Invalid_Engine);
}



static void
version_line_handler ( GpgmeCtx c, char *line )
{
    char *p;
    size_t len;

    lineno++;
    if ( c->out_of_core )
        return;
    if (!line)
        return; /* EOF */
    if (lineno==1) {
        if ( memcmp (line, "gpg ", 4) )
            return;
        if ( !(p = strpbrk (line, "0123456789")) )
            return;
        len = strcspn (p, " \t\r\n()<>" );
        p[len] = 0;
        tmp_engine_version = xtrystrdup (p);
    }
}


static const char *
get_engine_info (void)
{
    static const char *engine_info =NULL;
    GpgmeCtx c = NULL;
    GpgmeError err = 0;
    const char *path = NULL;

    /* FIXME: make sure that only one instance does run */
    if (engine_info)
        return engine_info;

    path = _gpgme_get_gpg_path ();
    err = gpgme_new (&c);
    if (err) 
        goto leave;
    err = _gpgme_gpg_new ( &c->gpg );
    if (err)
        goto leave;

    err = _gpgme_gpg_set_simple_line_handler ( c->gpg,
                                               version_line_handler, c );
    if (err)
        goto leave;

    _gpgme_gpg_add_arg ( c->gpg, "--version" );
    lineno = 0;
    xfree (tmp_engine_version); tmp_engine_version = NULL;
    err = _gpgme_gpg_spawn ( c->gpg, c );
    if (err)
        goto leave;
    gpgme_wait (c, 1);
    if (tmp_engine_version) {
        const char *fmt;
        char *p;

        fmt = "<GnupgInfo>\n"
              " <engine>\n"
              "  <version>%s</version>\n"
              "  <path>%s</path>\n"
              " </engine>\n"
              "</GnupgInfo>\n";
        /*(yes, I know that we allocating 2 extra bytes)*/
        p = xtrymalloc ( strlen(fmt) + strlen(path)
                         + strlen (tmp_engine_version) + 1);
        if (!p) {
            err = mk_error (Out_Of_Core);
            goto leave;
        }
        sprintf (p, fmt, tmp_engine_version, path);
        engine_info = p;
        xfree (tmp_engine_version); tmp_engine_version = NULL;
    }
    else {
        err = mk_error (General_Error);
    }

 leave:
    if (err) {
        const char *fmt;
        const char *errstr = gpgme_strerror (err);
        char *p;

        fmt = "<GnupgInfo>\n"
            " <engine>\n"
            "  <error>%s</error>\n"                
            "  <path>%s</path>\n"
            " </engine>\n"
            "</GnupgInfo>\n";

        p = xtrymalloc ( strlen(fmt) + strlen(errstr) + strlen(path) + 1);
        if (p) { 
            sprintf (p, fmt, errstr, path);
            engine_info = p;
        }
        else {
            engine_info = "<GnupgInfo>\n"
                          "  <error>Out of core</error>\n"
                          "</GnupgInfo>\n";
        }
    }
    gpgme_release ( c );
    return engine_info;
}






