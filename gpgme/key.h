/* key.h 
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

#ifndef KEY_H
#define KEY_H

#include <time.h>
#include "types.h"
#include "context.h"

struct certsig_s {
  struct certsig_s *next;
  struct {
    unsigned int revoked:1 ;
    unsigned int expired:1 ;
    unsigned int invalid:1 ;
  } flags;
  char keyid[16+1]; 
  time_t timestamp;  /* -1 for invalid, 0 for not available */
  time_t expires_at; /* 0 for does not expires */
};

struct subkey_s {
  struct subkey_s *next;
  unsigned int secret:1;
  struct {
    unsigned int revoked:1 ;
    unsigned int expired:1 ;
    unsigned int disabled:1 ;
    unsigned int invalid:1 ;
    unsigned int can_encrypt:1;
    unsigned int can_sign:1;
    unsigned int can_certify:1;
  } flags;
  unsigned int key_algo;
  unsigned int key_len;
  char keyid[16+1]; 
  char *fingerprint; /* malloced hex digits */
  time_t timestamp;  /* -1 for invalid, 0 for not available */
  time_t expires_at; /* 0 for does not expires */
};

struct gpgme_key_s {
  struct {
    unsigned int revoked:1 ;
    unsigned int expired:1 ;
    unsigned int disabled:1 ;
    unsigned int invalid:1 ;
    unsigned int can_encrypt:1;
    unsigned int can_sign:1;
    unsigned int can_certify:1;
  } gloflags; 
  unsigned int ref_count;
  unsigned int secret:1;
  unsigned int x509:1;
  char *issuer_serial; /* malloced string used only with X.509 */
  char *issuer_name;   /* ditto */
  char *chain_id;      /* ditto */
  GpgmeValidity otrust; /* only used with OpenPGP */
  struct subkey_s   keys; 
  struct user_id_s *uids;
};

void _gpgme_key_cache_init (void);
void _gpgme_key_cache_add (GpgmeKey key);
GpgmeKey _gpgme_key_cache_get (const char *fpr);


struct subkey_s *_gpgme_key_add_subkey (GpgmeKey key);
struct subkey_s *_gpgme_key_add_secret_subkey (GpgmeKey key);
GpgmeError _gpgme_key_append_name ( GpgmeKey key, const char *s );



#endif /* KEY_H */
