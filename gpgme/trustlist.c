/* trustlist.c - Trust item listing.
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

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "util.h"
#include "context.h"
#include "ops.h"

struct gpgme_trust_item_s
{
  int level;
  char keyid[16+1];
  int type;   
  char ot[2];
  char val[2];
  char *name;
};


static GpgmeTrustItem
trust_item_new (void)
{
  GpgmeTrustItem item;

  item = calloc (1, sizeof *item);
  return item;
}


static GpgmeError
trustlist_status_handler (GpgmeCtx ctx, GpgmeStatusCode code, char *args)
{
  switch (code)
    {
    case GPGME_STATUS_EOF:
      break;

    default:
      break;
    }
  return 0;
}


/* This handler is used to parse the output of --list-trust-path:
   Format:
   level:keyid:type:recno:ot:val:mc:cc:name:
   With TYPE = U for a user ID
               K for a key
   The RECNO is either the one of the dir record or the one of the uid
   record.  OT is the the usual trust letter and only availabel on K
   lines.  VAL is the calcualted validity MC is the marginal trust
   counter and only available on U lines CC is the same for the
   complete count NAME ist the username and only printed on U
   lines.  */
static GpgmeError
trustlist_colon_handler (GpgmeCtx ctx, char *line)
{
  char *p, *pend;
  int field = 0;
  GpgmeTrustItem item = NULL;

  if (!line)
    return 0; /* EOF */

  for (p = line; p; p = pend)
    {
      field++;
      pend = strchr (p, ':');
      if (pend) 
	*pend++ = 0;

      switch (field)
	{
	case 1: /* level */
	  item = trust_item_new ();
	  if (!item)
	    return GPGME_Out_Of_Core;
	  item->level = atoi (p);
	  break;
	case 2: /* long keyid */
	  if (strlen (p) == DIM(item->keyid) - 1)
	    strcpy (item->keyid, p);
	  break;
	case 3: /* type */
	  item->type = *p == 'K'? 1 : *p == 'U'? 2 : 0;
	  break;
	case 5: /* owner trust */
	  item->ot[0] = *p;
	  item->ot[1] = 0;
	  break;
	case 6: /* validity */
	  item->val[0] = *p;
	  item->val[1] = 0;
	  break;
	case 9: /* user ID */
	  item->name = strdup (p);
	  if (!item->name) {
	    gpgme_trust_item_release (item);
	    return GPGME_Out_Of_Core;
	  }
	  break;
        }
    }

  if (item)
    _gpgme_engine_io_event (ctx->engine, GPGME_EVENT_NEXT_TRUSTITEM, item);
  return 0;
}


void
_gpgme_op_trustlist_event_cb (void *data, GpgmeEventIO type, void *type_data)
{
  GpgmeCtx ctx = (GpgmeCtx) data;
  GpgmeTrustItem item = (GpgmeTrustItem) type_data;
  struct trust_queue_item_s *q, *q2;

  assert (type == GPGME_EVENT_NEXT_TRUSTITEM);

  q = malloc (sizeof *q);
  if (!q)
    {
      gpgme_trust_item_release (item);
      /* FIXME */
      /* ctx->error = GPGME_Out_Of_Core; */
      return;
    }
  q->item = item;
  q->next = NULL;
  /* FIXME: lock queue, keep a tail pointer */
  q2 = ctx->trust_queue;
  if (!q2)
    ctx->trust_queue = q;
  else
    {
      while (q2->next)
	q2 = q2->next;
      q2->next = q;
    }
  /* FIXME: unlock queue */
  ctx->key_cond = 1;
}


GpgmeError
gpgme_op_trustlist_start (GpgmeCtx ctx, const char *pattern, int max_level)
{
  GpgmeError err = 0;

  if (!pattern || !*pattern)
    return GPGME_Invalid_Value;

  err = _gpgme_op_reset (ctx, 2);
  if (err)
    goto leave;

  _gpgme_engine_set_status_handler (ctx->engine,
				    trustlist_status_handler, ctx);
  err = _gpgme_engine_set_colon_line_handler (ctx->engine,
					      trustlist_colon_handler, ctx);
  if (err)
    goto leave;

  err =_gpgme_engine_op_trustlist (ctx->engine, pattern);

 leave:
  if (err)
    {
      _gpgme_engine_release (ctx->engine);
      ctx->engine = NULL;
    }
  return err;
}


GpgmeError
gpgme_op_trustlist_next (GpgmeCtx ctx, GpgmeTrustItem *r_item)
{
  struct trust_queue_item_s *q;

  if (!r_item)
    return GPGME_Invalid_Value;
  *r_item = NULL;
  if (!ctx)
    return GPGME_Invalid_Value;

  if (!ctx->trust_queue)
    {
      GpgmeError err = _gpgme_wait_on_condition (ctx, &ctx->key_cond);
      if (err)
	return err;
      if (!ctx->key_cond)
	return GPGME_EOF;
      ctx->key_cond = 0; 
      assert (ctx->trust_queue);
    }
  q = ctx->trust_queue;
  ctx->trust_queue = q->next;

  *r_item = q->item;
  free (q);
  return 0;
}


/**
 * gpgme_op_trustlist_end:
 * @c: Context
 *
 * Ends the trustlist operation and allows to use the context for some
 * other operation next.
 **/
GpgmeError
gpgme_op_trustlist_end (GpgmeCtx ctx)
{
  if (!ctx)
    return GPGME_Invalid_Value;

  return 0;
}


void
gpgme_trust_item_release (GpgmeTrustItem item)
{
  if (!item)
    return;
  if (item->name)
    free (item->name);
  free (item);
}


const char *
gpgme_trust_item_get_string_attr (GpgmeTrustItem item, GpgmeAttr what,
				  const void *reserved, int idx)
{
  const char *val = NULL;

  if (!item)
    return NULL;
  if (reserved)
    return NULL;
  if (idx)
    return NULL;

  switch (what)
    {
    case GPGME_ATTR_KEYID:
      val = item->keyid;
      break;
    case GPGME_ATTR_OTRUST:  
      val = item->ot;
      break;
    case GPGME_ATTR_VALIDITY:
      val = item->val;
      break;
    case GPGME_ATTR_USERID:  
      val = item->name;
      break;
    default:
      break;
    }
  return val;
}


int
gpgme_trust_item_get_int_attr (GpgmeTrustItem item, GpgmeAttr what,
			       const void *reserved, int idx)
{
  int val = 0;
  
  if (!item)
    return 0;
  if (reserved)
    return 0;
  if (idx)
    return 0;

  switch (what)
    {
    case GPGME_ATTR_LEVEL:    
      val = item->level;
      break;
    case GPGME_ATTR_TYPE:    
      val = item->type;
      break;
    default:
      break;
    }
  return val;
}
