/* rungpg.h -  GPGME GnuPG engine calling functions.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002 g10 Code GmbH
 
   This file is part of GPGME.
 
   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with GPGME; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#ifndef RUNGPG_H
#define RUNGPG_H

#include "types.h"

const char *_gpgme_gpg_get_version (void);
GpgmeError _gpgme_gpg_check_version (void);

GpgmeError _gpgme_gpg_new (GpgObject *r_gpg);
void _gpgme_gpg_release (GpgObject gpg);
GpgmeError _gpgme_gpg_set_verbosity (GpgObject gpg, int verbosity);
void _gpgme_gpg_set_status_handler (GpgObject gpg, GpgmeStatusHandler fnc,
				    void *fnc_value);
GpgmeError _gpgme_gpg_set_colon_line_handler (GpgObject gpg,
					      GpgmeColonLineHandler fnc,
					      void *fnc_value);
GpgmeError _gpgme_gpg_set_command_handler (GpgObject gpg,
					   GpgmeCommandHandler fnc,
					   void *fnc_value,
					   GpgmeData linked_data);

GpgmeError _gpgme_gpg_op_decrypt (GpgObject gpg, GpgmeData ciph,
				  GpgmeData plain);
GpgmeError _gpgme_gpg_op_delete (GpgObject gpg, GpgmeKey key, int allow_secret);
GpgmeError _gpgme_gpg_op_edit (GpgObject gpg, GpgmeKey key, GpgmeData out,
			       GpgmeCtx ctx /* FIXME */);
GpgmeError _gpgme_gpg_op_encrypt (GpgObject gpg, GpgmeRecipients recp,
				  GpgmeData plain, GpgmeData ciph,
				  int use_armor);
GpgmeError _gpgme_gpg_op_encrypt_sign (GpgObject gpg, GpgmeRecipients recp,
				       GpgmeData plain, GpgmeData ciph,
				       int use_armor, GpgmeCtx ctx);
GpgmeError _gpgme_gpg_op_export (GpgObject gpg, GpgmeRecipients recp,
				 GpgmeData keydata, int use_armor);
GpgmeError _gpgme_gpg_op_genkey (GpgObject gpg, GpgmeData help_data,
				 int use_armor, GpgmeData pubkey,
				 GpgmeData seckey);
GpgmeError _gpgme_gpg_op_import (GpgObject gpg, GpgmeData keydata);
GpgmeError _gpgme_gpg_op_keylist (GpgObject gpg, const char *pattern,
				  int secret_only, int keylist_mode);
GpgmeError _gpgme_gpg_op_keylist_ext (GpgObject gpg, const char *pattern[],
				      int secret_only, int reserved,
				      int keylist_mode);
GpgmeError _gpgme_gpg_op_sign (GpgObject gpg, GpgmeData in, GpgmeData out,
			       GpgmeSigMode mode, int use_armor,
			       int use_textmode, GpgmeCtx ctx /* FIXME */);
GpgmeError _gpgme_gpg_op_trustlist (GpgObject gpg, const char *pattern);
GpgmeError _gpgme_gpg_op_verify (GpgObject gpg, GpgmeData sig,
				 GpgmeData signed_text,
				 GpgmeData plaintext);
GpgmeError _gpgme_gpg_spawn (GpgObject gpg, void *opaque);
void _gpgme_gpg_set_io_cbs (GpgObject gpg, struct GpgmeIOCbs *io_cbs);
void _gpgme_gpg_io_event (GpgObject gpg, GpgmeEventIO type, void *type_data);

#endif /* RUNGPG_H */
