/* parsetlv.c -  ASN.1 TLV functions
 * Copyright (C) 2005, 2007, 2008, 2012 g10 Code GmbH
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parsetlv.h"


/* Simple but pretty complete ASN.1 BER parser.  Parse the data at the
   address of BUFFER with a length given at the address of SIZE.  On
   success return 0 and update BUFFER and SIZE to point to the value.
   Do not update them on error.  The information about the object are
   stored in the caller allocated TI structure.  */
int
_gpgme_parse_tlv (char const **buffer, size_t *size, tlvinfo_t *ti)
{
  int c;
  unsigned long tag;
  const unsigned char *buf = (const unsigned char *)(*buffer);
  size_t length = *size;

  ti->cls = 0;
  ti->tag = 0;
  ti->is_cons = 0;
  ti->is_ndef = 0;
  ti->length = 0;
  ti->nhdr = 0;

  if (!length)
    return -1;
  c = *buf++; length--; ++ti->nhdr;

  ti->cls = (c & 0xc0) >> 6;
  ti->is_cons = !!(c & 0x20);
  tag = c & 0x1f;

  if (tag == 0x1f)
    {
      tag = 0;
      do
        {
          tag <<= 7;
          if (!length)
            return -1;
          c = *buf++; length--; ++ti->nhdr;
          tag |= c & 0x7f;
        }
      while (c & 0x80);
    }
  ti->tag = tag;

  if (!length)
    return -1;
  c = *buf++; length--; ++ti->nhdr;

  if ( !(c & 0x80) )
    ti->length = c;
  else if (c == 0x80)
    ti->is_ndef = 1;
  else if (c == 0xff)
    return -1;
  else
    {
      unsigned long len = 0;
      int count = (c & 0x7f);

      if (count > sizeof (len) || count > sizeof (size_t))
        return -1;

      for (; count; count--)
        {
          len <<= 8;
          if (!length)
            return -1;
          c = *buf++; length--; ++ti->nhdr;
          len |= c & 0xff;
        }
      ti->length = len;
    }

  *buffer = (void*)buf;
  *size = length;
  return 0;
}
