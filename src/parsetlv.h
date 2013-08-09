/* parsetlv.h -  TLV functions defintions
 * Copyright (C) 2012 g10 Code GmbH
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

#ifndef PARSETLV_H
#define PARSETLV_H

/* ASN.1 constants.  */
#define ASN1_CLASS_UNIVERSAL   0
#define ASN1_CLASS_APPLICATION 1
#define ASN1_CLASS_CONTEXT     2
#define ASN1_CLASS_PRIVATE     3
#define ASN1_TAG_INTEGER       2
#define ASN1_TAG_OBJECT_ID     6
#define ASN1_TAG_SEQUENCE     16


/* Object used with parse_tlv.  */
struct tlvinfo_s
{
  int cls;            /* The class of the tag.  */
  int tag;            /* The tag.  */
  int is_cons;        /* True if it is a constructed object.  */
  int is_ndef;        /* True if the object has an indefinite length.  */
  size_t length;      /* The length of the value.  */
  size_t nhdr;        /* The number of octets in the header (tag,length). */
};
typedef struct tlvinfo_s tlvinfo_t;

/*-- parsetlv.c --*/
int _gpgme_parse_tlv (char const **buffer, size_t *size, tlvinfo_t *ti);
#define parse_tlv(a,b,c) _gpgme_parse_tlv ((a), (b), (c))


#endif /*PARSETLV_H*/
