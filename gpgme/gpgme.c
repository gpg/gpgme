/* gpgme.c -  GnuPG Made Easy
 *	Copyright (C) 2000 Werner Koch (dd9jn)
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
#include <assert.h>

#include "util.h"
#include "context.h"
#include "ops.h"

#define my_isdigit(a)  ( (a) >='0' && (a) <= '9' )
#define my_isxdigit(a) ( my_isdigit((a))               \
                         || ((a) >= 'A' && (a) <= 'F') \
                         || ((a) >= 'f' && (a) <= 'f') )

/**
 * gpgme_new:
 * @r_ctx: Returns the new context
 * 
 * Create a new context to be used with most of the other GPGME
 * functions.  Use gpgme_release_contect() to release all resources
 *
 * Return value: An error code 
 **/
GpgmeError
gpgme_new (GpgmeCtx *r_ctx)
{
    GpgmeCtx c;

    c = xtrycalloc ( 1, sizeof *c );
    if (!c)
        return mk_error (Out_Of_Core);
    c->verbosity = 1;
    *r_ctx = c;

    return 0;
}

/**
 * gpgme_release:
 * @c: Context to be released. 
 * 
 * Release all resources associated with the given context.
 **/
void
gpgme_release ( GpgmeCtx c )
{
    if (!c)
        return;
    _gpgme_gpg_release ( c->gpg ); 
    _gpgme_release_result ( c );
    gpgme_key_release ( c->tmp_key );
    gpgme_data_release ( c->help_data_1 );
    gpgme_data_release ( c->notation );
    gpgme_signers_clear (c);
    if (c->signers)
        xfree (c->signers);
    /* fixme: release the key_queue */
    xfree (c);
}


void
_gpgme_release_result ( GpgmeCtx c )
{
    switch (c->result_type) {
      case RESULT_TYPE_NONE:
        break;
      case RESULT_TYPE_VERIFY:
        _gpgme_release_verify_result ( c->result.verify );
        break;
      case RESULT_TYPE_DECRYPT:
        _gpgme_release_decrypt_result ( c->result.decrypt );
        break;
      case RESULT_TYPE_SIGN:
        _gpgme_release_sign_result ( c->result.sign );
        break;
    }

    c->result.verify = NULL;
    c->result_type = RESULT_TYPE_NONE;
}


/**
 * gpgme_cancel:
 * @c: the context
 * 
 * Cancel the current operation.  It is not guaranteed that it will work for
 * all kinds of operations.  It is especially useful in a passphrase callback
 * to stop the system from asking another time for the passphrase.
 **/

void
gpgme_cancel (GpgmeCtx c)
{
    return_if_fail (c);

    c->cancel = 1;
}

/**
 * gpgme_get_notation:
 * @c: the context 
 * 
 * If there is notation data available from the last signature check, this
 * function may be used to return this notation data as a string.  The string
 * is an XML represantaton of that data embedded in a %<notation> container.
 * 
 * Return value: An XML string or NULL if no notation data is available.
 **/
char *
gpgme_get_notation ( GpgmeCtx c )
{
    if ( !c->notation )
        return NULL;
    return _gpgme_data_get_as_string ( c->notation );
}

/**
 * gpgme_set_armor:
 * @c: the contect 
 * @yes: boolean value to set or clear that flag
 * 
 * Enable or disable the use of an ascii armor for all output.  
 **/
void
gpgme_set_armor ( GpgmeCtx c, int yes )
{
    if ( !c )
        return; /* oops */
    c->use_armor = yes;
}

/**
 * gpgme_set_textmode:
 * @c: the context 
 * @yes: boolean flag whether textmode should be enabled
 * 
 * Enable or disable the use of the special textmode.  Textmode is for example
 * used for MIME (RFC2015) signatures
 **/
void
gpgme_set_textmode ( GpgmeCtx c, int yes )
{
    if ( !c )
        return; /* oops */
    c->use_textmode = yes;
}

/**
 * gpgme_set_keylist_mode:
 * @c: the context
 * @mode: listing mode
 * 
 * This function changes the default behaviour of the keylisting functions.
 * Defines values for @mode are: %0 = normal, %1 = fast listing without
 * information about key validity.
 **/
void
gpgme_set_keylist_mode ( GpgmeCtx c, int mode )
{
    if (!c)
        return;
    c->keylist_mode = mode;
}


/**
 * gpgme_set_passphrase_cb:
 * @c: the context 
 * @cb: A callback function
 * @cb_value: The value passed to the callback function
 * 
 * This function sets a callback function to be used to pass a passphrase
 * to gpg. The preferred way to handle this is by using the gpg-agent, but
 * because that beast is not ready for real use, you can use this passphrase
 * thing.
 *
 * The callback function is defined as:
 * <literal>
 * typedef const char *(*GpgmePassphraseCb)(void*cb_value,
 *                                          const char *desc,
 *                                          void *r_hd);
 * </literal>
 * and called whenever gpgme needs a passphrase. DESC will have a nice
 * text, to be used to prompt for the passphrase and R_HD is just a parameter
 * to be used by the callback it self.  Becuase the callback returns a const
 * string, the callback might want to know when it can release resources
 * assocated with that returned string; gpgme helps here by calling this
 * passphrase callback with an DESC of %NULL as soon as it does not need
 * the returned string anymore.  The callback function might then choose
 * to release resources depending on R_HD.
 *
 **/
void
gpgme_set_passphrase_cb ( GpgmeCtx c, GpgmePassphraseCb cb, void *cb_value )
{
    c->passphrase_cb = cb;
    c->passphrase_cb_value = cb_value;
}

/**
 * gpgme_set_pprogress_cb:
 * @c: the context 
 * @cb: A callback function
 * @cb_value: The value passed to the callback function
 * 
 * This function sets a callback function to be used as a progress indicator.
 *
 * The callback function is defined as:
 * <literal>
 * typedef void (*GpgmeProgressCb) (void*cb_value,
 *                                  const char *what, int type,
 *                                  int curretn, int total);
 * </literal>
 * For details on the progress events, see the entry for the PROGRESS
 * status in the file doc/DETAILS of the GnuPG distribution.
 **/
void
gpgme_set_progress_cb ( GpgmeCtx c, GpgmeProgressCb cb, void *cb_value )
{
    c->progress_cb = cb;
    c->progress_cb_value = cb_value;
}









