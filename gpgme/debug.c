/* debug.c
 *	Copyright (C) 2001 Werner Koch (dd9jn)
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
#include <stdarg.h>
#include <assert.h>

#include "util.h"
#include "sema.h"

DEFINE_STATIC_LOCK (debug_lock);

struct debug_control_s {
    FILE *fp;
    char fname[100];
};

static int debug_level = 0;

static void
debug_init (void)
{
    static volatile int initialized = 0;
       
    if (initialized) 
        return;
    LOCK (debug_lock);
    if (!initialized) {
        const char *e = getenv ("GPGME_DEBUG");
        
        debug_level =  e? atoi (e): 0;
        initialized = 1;
        if (debug_level > 0)
            fprintf (stderr,"gpgme_debug: level=%d\n", debug_level);
    }
    UNLOCK (debug_lock);
}


void
_gpgme_debug (int level, const char *format, ...)
{
    va_list arg_ptr ;

    debug_init ();
    if ( debug_level < level )
        return;
    
    va_start ( arg_ptr, format ) ;
    LOCK (debug_lock);
    vfprintf (stderr, format, arg_ptr) ;
    va_end ( arg_ptr ) ;
    if( format && *format && format[strlen(format)-1] != '\n' )
        putc ('\n', stderr);
    UNLOCK (debug_lock);
    fflush (stderr);
}



void
_gpgme_debug_begin ( void **helper, int level, const char *text)
{
    struct debug_control_s *ctl;

    debug_init ();

    *helper = NULL;
    if ( debug_level < level )
        return;
    ctl = xtrycalloc (1, sizeof *ctl );
    if (!ctl) {
        _gpgme_debug (255, __FILE__ ":" STR2(__LINE__)": out of core");
        return;
    }

    /* Oh what a pitty that we don't have a asprintf or snprintf under
     * Windoze.  We definitely should write our own clib for W32! */
    sprintf ( ctl->fname, "/tmp/gpgme_debug.%d.%p", getpid (), ctl );
    ctl->fp = fopen (ctl->fname, "w+");
    if (!ctl->fp) {
        _gpgme_debug (255,__FILE__ ":" STR2(__LINE__)": failed to create `%s'",
                      ctl->fname );
        xfree (ctl);
        return;
    }
    *helper = ctl;
    _gpgme_debug_add (helper, "%s", text );
}

int
_gpgme_debug_enabled (void **helper)
{
    return helper && *helper;
}


void
_gpgme_debug_add (void **helper, const char *format, ...)
{
    struct debug_control_s *ctl = *helper;
    va_list arg_ptr ;

    if ( !*helper )
        return;
    
    va_start ( arg_ptr, format ) ;
    vfprintf (ctl->fp, format, arg_ptr) ;
    va_end ( arg_ptr ) ;
}

void
_gpgme_debug_end (void **helper, const char *text)
{
    struct debug_control_s *ctl = *helper;
    int c, last_c=EOF;

    if ( !*helper )
        return;
    
    _gpgme_debug_add (helper, "%s", text );
    fflush (ctl->fp); /* we need this for the buggy Windoze libc */
    rewind (ctl->fp);
    LOCK (debug_lock);
    while ( (c=getc (ctl->fp)) != EOF ) {
        putc (c, stderr);
        last_c = c;
    }
    if (last_c != '\n')
        putc ('\n', stderr);
    UNLOCK (debug_lock);
    
    fclose (ctl->fp);
    remove (ctl->fname);
    xfree (ctl);
    *helper = NULL;
}

