/* key.h - Key handling interface.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003 g10 Code GmbH

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

#ifndef KEY_H
#define KEY_H

#include <time.h>
#include "context.h"


struct certsig_s
{
  struct certsig_s *next;
  struct
  {
    unsigned int revoked : 1;
    unsigned int expired : 1;
    unsigned int invalid : 1;
    unsigned int exportable : 1;
  } flags;
  unsigned int algo;
  char keyid[16 + 1]; 
  time_t timestamp;		/* -1 for invalid, 0 for not available.  */
  time_t expires_at;		/* 0 for no expiration.  */
  GpgmeSigStat sig_stat;
  unsigned int sig_class;
  const char *name_part;	/* All 3 point into strings behind name  */
  const char *email_part;	/* or to read-only strings.  */
  const char *comment_part;
  char name[1];
};


struct subkey_s
{
  struct subkey_s *next;
  unsigned int secret:1;
  struct
  {
    unsigned int revoked : 1;
    unsigned int expired : 1;
    unsigned int disabled : 1;
    unsigned int invalid : 1;
    unsigned int can_encrypt : 1;
    unsigned int can_sign : 1;
    unsigned int can_certify : 1;
  } flags;
  unsigned int key_algo;
  unsigned int key_len;
  char keyid[16 + 1];
  char *fingerprint;	/* Malloced hex digits.  */
  time_t timestamp;	/* -1 for invalid, 0 for not available.  */
  time_t expires_at;	/* 0 for does not expires.  */
};


struct gpgme_key_s
{
  struct
  {
    unsigned int revoked : 1;
    unsigned int expired : 1;
    unsigned int disabled : 1;
    unsigned int invalid : 1;
    unsigned int can_encrypt : 1;
    unsigned int can_sign : 1;
    unsigned int can_certify : 1;
  } gloflags;
  unsigned int ref_count;
  unsigned int secret : 1;
  unsigned int x509 : 1;
  char *issuer_serial;	/* Malloced string used only with X.509.  */
  char *issuer_name;	/* Ditto.  */
  char *chain_id;	/* Ditto.  */
  GpgmeValidity otrust;	/* Only used with OpenPGP.  */
  struct subkey_s keys;
  struct user_id_s *uids;
  struct user_id_s *last_uid;
};


void _gpgme_key_cache_init (void);
void _gpgme_key_cache_add (GpgmeKey key);
GpgmeKey _gpgme_key_cache_get (const char *fpr);


struct certsig_s *_gpgme_key_add_certsig (GpgmeKey key, char *src);
struct subkey_s *_gpgme_key_add_subkey (GpgmeKey key);
struct subkey_s *_gpgme_key_add_secret_subkey (GpgmeKey key);
GpgmeError _gpgme_key_append_name (GpgmeKey key, const char *str);

#endif	/* KEY_H */
