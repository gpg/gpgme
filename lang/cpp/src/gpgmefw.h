/*
  gpgmefw.h - Forwards declarations for gpgme (0.3 and 0.4)
  Copyright (C) 2004 Klarälvdalens Datakonsult AB
  2016 Bundesamt für Sicherheit in der Informationstechnik
  Software engineering by Intevation GmbH

  This file is part of GPGME++.

  GPGME++ is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General Public
  License as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  GPGME++ is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Library General Public License for more details.

  You should have received a copy of the GNU Library General Public License
  along with GPGME++; see the file COPYING.LIB.  If not, write to the
  Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  Boston, MA 02110-1301, USA.
*/

#ifndef __GPGMEPP_GPGMEFW_H__
#define __GPGMEPP_GPGMEFW_H__

struct gpgme_context;
typedef gpgme_context *gpgme_ctx_t;

struct gpgme_data;
typedef gpgme_data *gpgme_data_t;

struct gpgme_io_cbs;

struct _gpgme_key;
typedef struct _gpgme_key *gpgme_key_t;

struct _gpgme_trust_item;
typedef struct _gpgme_trust_item *gpgme_trust_item_t;

struct _gpgme_subkey;
typedef struct _gpgme_subkey *gpgme_sub_key_t;

struct _gpgme_user_id;
typedef struct _gpgme_user_id *gpgme_user_id_t;

struct _gpgme_key_sig;
typedef struct _gpgme_key_sig *gpgme_key_sig_t;

struct _gpgme_sig_notation;
typedef struct _gpgme_sig_notation *gpgme_sig_notation_t;

struct _gpgme_engine_info;
typedef struct _gpgme_engine_info *gpgme_engine_info_t;

struct _gpgme_op_keylist_result;
typedef struct _gpgme_op_keylist_result *gpgme_keylist_result_t;

struct _gpgme_recipient;
typedef struct _gpgme_recipient *gpgme_recipient_t;

struct gpgme_conf_opt;
typedef struct gpgme_conf_opt *gpgme_conf_opt_t;

struct gpgme_conf_comp;
typedef struct gpgme_conf_comp *gpgme_conf_comp_t;

struct gpgme_conf_arg;
typedef struct gpgme_conf_arg *gpgme_conf_arg_t;

struct _gpgme_tofu_info;
typedef struct _gpgme_tofu_info *gpgme_tofu_info_t;

struct _gpgme_op_query_swdb_result;
typedef struct _gpgme_op_query_swdb_result *gpgme_query_swdb_result_t;

#endif // __GPGMEPP_GPGMEFW_H__
