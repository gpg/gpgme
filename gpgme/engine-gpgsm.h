/* engine-gpgsm.h -  GPGME GpgSM engine calling functions
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

#ifndef ENGINE_GPGSM_H
#define ENGINE_GPGSM_H

#include "types.h"
#include "rungpg.h" /* FIXME statusHandler */

const char *_gpgme_gpgsm_get_version (void);
GpgmeError _gpgme_gpgsm_check_version (void);

GpgmeError _gpgme_gpgsm_new (GpgsmObject *r_gpg);
void _gpgme_gpgsm_release (GpgsmObject gpg);

void _gpgme_gpgsm_set_status_handler (GpgsmObject gpgsm,
				      GpgStatusHandler fnc, void *fnc_value);
void _gpgme_gpgsm_set_colon_line_handler (GpgsmObject gpgsm,
                                   GpgColonLineHandler fnc, void *fnc_value) ;
GpgmeError _gpgme_gpgsm_op_decrypt (GpgsmObject gpgsm, GpgmeData ciph,
				    GpgmeData plain);
GpgmeError _gpgme_gpgsm_op_delete (GpgsmObject gpgsm, GpgmeKey key,
				   int allow_secret);
GpgmeError _gpgme_gpgsm_op_encrypt (GpgsmObject gpgsm, GpgmeRecipients recp,
				    GpgmeData plain, GpgmeData ciph,
				    int use_armor);
GpgmeError _gpgme_gpgsm_op_export (GpgsmObject gpgsm, GpgmeRecipients recp,
				   GpgmeData keydata, int use_armor);
GpgmeError _gpgme_gpgsm_op_genkey (GpgsmObject gpgsm, GpgmeData help_data,
				   int use_armor);
GpgmeError _gpgme_gpgsm_op_import (GpgsmObject gpgsm, GpgmeData keydata);
GpgmeError _gpgme_gpgsm_op_keylist (GpgsmObject gpgsm, const char *pattern,
				    int secret_only, int keylist_mode);
GpgmeError _gpgme_gpgsm_op_sign (GpgsmObject gpgsm, GpgmeData in,
				 GpgmeData out,
				 GpgmeSigMode mode, int use_armor,
				 int use_textmode, GpgmeCtx ctx /* FIXME */);
GpgmeError _gpgme_gpgsm_op_trustlist (GpgsmObject gpgsm, const char *pattern);
GpgmeError _gpgme_gpgsm_op_verify (GpgsmObject gpgsm, GpgmeData sig,
				   GpgmeData text);
GpgmeError _gpgme_gpgsm_start (GpgsmObject gpgsm, void *opaque);

#endif /* ENGINE_GPGSM_H */
