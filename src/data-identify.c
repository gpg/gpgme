/* data-identify.c - Try to identify the data
 * Copyright (C) 2013, 2016 g10 Code GmbH
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "gpgme.h"
#include "data.h"
#include "util.h"
#include "parsetlv.h"


/* The size of the sample data we take for detection.  */
#define SAMPLE_SIZE 2048


/* OpenPGP packet types.  */
enum
  {
    PKT_NONE	      = 0,
    PKT_PUBKEY_ENC    = 1,  /* Public key encrypted packet. */
    PKT_SIGNATURE     = 2,  /* Secret key encrypted packet. */
    PKT_SYMKEY_ENC    = 3,  /* Session key packet. */
    PKT_ONEPASS_SIG   = 4,  /* One pass sig packet. */
    PKT_SECRET_KEY    = 5,  /* Secret key. */
    PKT_PUBLIC_KEY    = 6,  /* Public key. */
    PKT_SECRET_SUBKEY = 7,  /* Secret subkey. */
    PKT_COMPRESSED    = 8,  /* Compressed data packet. */
    PKT_ENCRYPTED     = 9,  /* Conventional encrypted data. */
    PKT_MARKER	      = 10, /* Marker packet. */
    PKT_PLAINTEXT     = 11, /* Literal data packet. */
    PKT_RING_TRUST    = 12, /* Keyring trust packet. */
    PKT_USER_ID	      = 13, /* User id packet. */
    PKT_PUBLIC_SUBKEY = 14, /* Public subkey. */
    PKT_OLD_COMMENT   = 16, /* Comment packet from an OpenPGP draft. */
    PKT_ATTRIBUTE     = 17, /* PGP's attribute packet. */
    PKT_ENCRYPTED_MDC = 18, /* Integrity protected encrypted data. */
    PKT_MDC 	      = 19, /* Manipulation detection code packet. */
  };


static inline unsigned long
buf32_to_ulong (const void *buffer)
{
  const unsigned char *p = buffer;

  return (((unsigned long)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}


/* Parse the next openpgp packet.  This function assumes a valid
 * OpenPGP packet at the address pointed to by BUFPTR which has a
 * maximum length as stored at BUFLEN.  Return the header information
 * of that packet and advance the pointer stored at BUFPTR to the next
 * packet; also adjust the length stored at BUFLEN to match the
 * remaining bytes. If there are no more packets, store NULL at
 * BUFPTR.  Return an non-zero error code on failure or the following
 * data on success:
 *
 *  R_PKTTYPE = The packet type.
 *  R_NTOTAL  = The total number of bytes of this packet
 *
 * If GPG_ERR_TRUNCATED is returned, a packet type is anyway stored at
 * R_PKTTYPE but R_NOTAL won't have a usable value,
 */
static gpg_error_t
next_openpgp_packet (unsigned char const **bufptr, size_t *buflen,
                     int *r_pkttype, size_t *r_ntotal)
{
  const unsigned char *buf = *bufptr;
  size_t len = *buflen;
  int c, ctb, pkttype;
  unsigned long pktlen;

  if (!len)
    return gpg_error (GPG_ERR_NO_DATA);

  /* First some blacklisting.  */
  if (len >= 4 && !memcmp (buf, "\x89PNG", 4))
    return gpg_error (GPG_ERR_INV_PACKET); /* This is a PNG file.  */

  /* Start parsing.  */
  ctb = *buf++; len--;
  if ( !(ctb & 0x80) )
    return gpg_error (GPG_ERR_INV_PACKET); /* Invalid CTB. */

  if ((ctb & 0x40))  /* New style (OpenPGP) CTB.  */
    {
      pkttype = (ctb & 0x3f);
      if (!len)
        return gpg_error (GPG_ERR_INV_PACKET); /* No 1st length byte. */
      c = *buf++; len--;
      if ( c < 192 )
        pktlen = c;
      else if ( c < 224 )
        {
          pktlen = (c - 192) * 256;
          if (!len)
            return gpg_error (GPG_ERR_INV_PACKET); /* No 2nd length byte. */
          c = *buf++; len--;
          pktlen += c + 192;
        }
      else if (c == 255)
        {
          if (len < 4)
            return gpg_error (GPG_ERR_INV_PACKET); /* No length bytes. */
          pktlen = buf32_to_ulong (buf);
          buf += 4;
          len -= 4;
        }
      else /* Partial length encoding. */
        {
          pktlen = 0;
        }
    }
  else /* Old style CTB.  */
    {
      int lenbytes;

      pktlen = 0;
      pkttype = (ctb>>2)&0xf;
      lenbytes = ((ctb&3)==3)? 0 : (1<<(ctb & 3));
      if (len < lenbytes)
        return gpg_error (GPG_ERR_INV_PACKET); /* Not enough length bytes.  */
      for (; lenbytes; lenbytes--)
        {
          pktlen <<= 8;
          pktlen |= *buf++; len--;
	}
    }

  /* Do some basic sanity check.  */
  switch (pkttype)
    {
    case PKT_PUBKEY_ENC:
    case PKT_SIGNATURE:
    case PKT_SYMKEY_ENC:
    case PKT_ONEPASS_SIG:
    case PKT_SECRET_KEY:
    case PKT_PUBLIC_KEY:
    case PKT_SECRET_SUBKEY:
    case PKT_COMPRESSED:
    case PKT_ENCRYPTED:
    case PKT_MARKER:
    case PKT_PLAINTEXT:
    case PKT_RING_TRUST:
    case PKT_USER_ID:
    case PKT_PUBLIC_SUBKEY:
    case PKT_OLD_COMMENT:
    case PKT_ATTRIBUTE:
    case PKT_ENCRYPTED_MDC:
    case PKT_MDC:
      break; /* Okay these are allowed packets. */
    default:
      return gpg_error (GPG_ERR_UNEXPECTED);
    }

  if (pktlen > len)
    {
      /* Packet length header too long.  This is possible because we
       * may have only a truncated image.  */
      *r_pkttype = pkttype;
      *r_ntotal = 0;
      *bufptr = NULL;
      return gpg_error (GPG_ERR_TRUNCATED);
    }

  *r_pkttype = pkttype;
  *r_ntotal = (buf - *bufptr) + pktlen;

  *bufptr = buf + pktlen;
  *buflen = len - pktlen;
  if (!*buflen)
    *bufptr = NULL;

  return 0;
}


/* Detection of PGP binary data.  This function parses an OpenPGP
 * message.  This parser is robust enough to work on a truncated
 * version.  Returns a GPGME_DATA_TYPE_.  */
static gpgme_data_type_t
pgp_binary_detection (const void *image_arg, size_t imagelen)
{
  gpg_error_t err = 0;
  const unsigned char *image = image_arg;
  size_t n;
  int pkttype;
  int anypacket = 0;
  int allsignatures = 0;

  while (!err && image)
    {
      err = next_openpgp_packet (&image, &imagelen, &pkttype, &n);
      if (gpg_err_code (err) == GPG_ERR_TRUNCATED)
        ;
      else if (err)
        break;

      /* Skip all leading marker packets.  */
      if (!anypacket && pkttype == PKT_MARKER)
        continue;

      if (pkttype == PKT_SIGNATURE)
        {
          if (!anypacket)
            allsignatures = 1;
        }
      else
        allsignatures = 0;

      switch (pkttype)
        {
        case PKT_SIGNATURE:
          break;  /* We decide later.  */

        case PKT_PLAINTEXT:
          /* Old style signature format: {sig}+,plaintext */
          if (allsignatures)
            return GPGME_DATA_TYPE_PGP_SIGNED;
          break;

        case PKT_ONEPASS_SIG:
          return GPGME_DATA_TYPE_PGP_SIGNED;

        case PKT_SECRET_KEY:
        case PKT_PUBLIC_KEY:
          return GPGME_DATA_TYPE_PGP_KEY;

        case PKT_SECRET_SUBKEY:
        case PKT_PUBLIC_SUBKEY:
          return GPGME_DATA_TYPE_PGP_OTHER;
        case PKT_PUBKEY_ENC:
        case PKT_SYMKEY_ENC:
          return GPGME_DATA_TYPE_PGP_ENCRYPTED;

        case PKT_COMPRESSED:
          /* If this is the first packet we assume that that a signed
           * packet follows.  We do not want to uncompress it here due
           * to the need of a lot of code and the potential DoS. */
          if (!anypacket)
            return GPGME_DATA_TYPE_PGP_SIGNED;
          return GPGME_DATA_TYPE_PGP_OTHER;

        default:
          return GPGME_DATA_TYPE_PGP_OTHER;
        }
      anypacket = 1;
    }

  if (allsignatures)
    return  GPGME_DATA_TYPE_PGP_SIGNATURE;

  return GPGME_DATA_TYPE_UNKNOWN;
}


/* This is probably an armored "PGP MESSAGE" which can encode
 * different PGP data types.  STRING is modified after a call to this
 * function. */
static gpgme_data_type_t
inspect_pgp_message (char *string)
{
  struct b64state state;
  size_t nbytes;

  if (_gpgme_b64dec_start (&state, ""))
    return GPGME_DATA_TYPE_INVALID; /* oops */

  if (_gpgme_b64dec_proc (&state, string, strlen (string), &nbytes))
    {
      _gpgme_b64dec_finish (&state);
      return GPGME_DATA_TYPE_UNKNOWN; /* bad encoding etc. */
    }
  _gpgme_b64dec_finish (&state);
  string[nbytes] = 0; /* Better append a Nul. */

  return pgp_binary_detection (string, nbytes);
}


/* Note that DATA may be binary but a final nul is required so that
   string operations will find a terminator.

   Returns: GPGME_DATA_TYPE_xxxx */
static gpgme_data_type_t
basic_detection (char *data, size_t datalen)
{
  tlvinfo_t ti;
  const char *s;
  size_t n;
  int maybe_p12 = 0;

  if (datalen < 24) /* Object is probably too short for detection.  */
    return GPGME_DATA_TYPE_UNKNOWN;

  /* This is a common example of a CMS object - it is obvious that we
     only need to read a few bytes to get to the OID:
  30 82 0B 59 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 0B 4A 30 82 0B 46 02
  ----------- ++++++++++++++++++++++++++++++++
  SEQUENCE    OID (signedData)
  (2 byte len)

    A PKCS#12 message is:

  30 82 08 59 02 01 03 30 82 08 1F 06 09 2A 86 48 86 F7 0D 01 07 01 A0 82
  ----------- ++++++++ ----------- ++++++++++++++++++++++++++++++++
  SEQUENCE    INTEGER  SEQUENCE    OID (data)

    A X.509 certificate is:

  30 82 05 B8 30 82 04 A0 A0 03 02 01 02 02 07 15 46 A0 BF 30 07 39 30 0D
  ----------- +++++++++++ ----- ++++++++ --------------------------
  SEQUENCE    SEQUENCE    [0]   INTEGER  INTEGER                    SEQU
              (tbs)            (version) (s/n)                      (Algo)

    Thus we need to read at least 22 bytes, we add 2 bytes to cope
    with length headers stored with 4 bytes.  For a v0 certificate the
    tag and the bersion are missin (they are implicit) - detect this
    too as a cert becuase some root CA use this.
  */


  s = data;
  n = datalen;

  if (parse_tlv (&s, &n, &ti))
    goto try_pgp; /* Not properly BER encoded.  */
  if (!(ti.cls == ASN1_CLASS_UNIVERSAL && ti.tag == ASN1_TAG_SEQUENCE
        && ti.is_cons))
    goto try_pgp; /* A CMS object always starts with a sequence.  */

  if (parse_tlv (&s, &n, &ti))
    goto try_pgp; /* Not properly BER encoded.  */
  if (ti.cls == ASN1_CLASS_UNIVERSAL && ti.tag == ASN1_TAG_SEQUENCE
      && ti.is_cons && n >= ti.length)
    {
      if (parse_tlv (&s, &n, &ti))
        goto try_pgp;
      if (ti.cls == ASN1_CLASS_CONTEXT && ti.tag == 0
          && ti.is_cons && ti.length == 3 && n >= ti.length)
        {
          if (parse_tlv (&s, &n, &ti))
            goto try_pgp;
          if (!(ti.cls == ASN1_CLASS_UNIVERSAL && ti.tag == ASN1_TAG_INTEGER
                && !ti.is_cons && ti.length == 1 && n && (*s == 1 || *s == 2)))
            goto try_pgp;
          s++;
          n--;
          if (!(ti.cls == ASN1_CLASS_UNIVERSAL && ti.tag == ASN1_TAG_INTEGER
                && !ti.is_cons))
            goto try_pgp;
          /* Because the now following S/N may be larger than the sample
             data we have, we stop parsing here and don't check for the
             algorithm ID.  */
          return GPGME_DATA_TYPE_X509_CERT;  /* regular cert.  */
        }
      if (ti.cls == ASN1_CLASS_UNIVERSAL && ti.tag == ASN1_TAG_INTEGER
          && !ti.is_cons)
        {
          /* Because this S/N may be larger than the sample data we
             have, we can't check that a SEQUENCE follows.  */
          return GPGME_DATA_TYPE_X509_CERT;  /* v0 cert with implict tag.  */
        }

      goto try_pgp;

    }
  if (ti.cls == ASN1_CLASS_UNIVERSAL && ti.tag == ASN1_TAG_INTEGER
      && !ti.is_cons && ti.length == 1 && n && *s == 3)
    {
      maybe_p12 = 1;
      s++;
      n--;
      if (parse_tlv (&s, &n, &ti))
        goto try_pgp;
      if (!(ti.cls == ASN1_CLASS_UNIVERSAL && ti.tag == ASN1_TAG_SEQUENCE
            && ti.is_cons))
        goto try_pgp;
      if (parse_tlv (&s, &n, &ti))
        goto try_pgp;
    }
  if (ti.cls == ASN1_CLASS_UNIVERSAL && ti.tag == ASN1_TAG_OBJECT_ID
      && !ti.is_cons && ti.length && n >= ti.length)
    {
      if (ti.length == 9)
        {
          if (!memcmp (s, "\x2A\x86\x48\x86\xF7\x0D\x01\x07\x01", 9))
            {
              /* Data.  */
              return (maybe_p12 ? GPGME_DATA_TYPE_PKCS12
                      /*     */ : GPGME_DATA_TYPE_CMS_OTHER);
            }
          if (!memcmp (s, "\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02", 9))
            {
              /* Signed Data.  */
              return (maybe_p12 ? GPGME_DATA_TYPE_PKCS12
                      /*     */ : GPGME_DATA_TYPE_CMS_SIGNED);
            }
          if (!memcmp (s, "\x2A\x86\x48\x86\xF7\x0D\x01\x07\x03", 9))
            return GPGME_DATA_TYPE_CMS_ENCRYPTED; /* Enveloped Data.  */
          if (!memcmp (s, "\x2A\x86\x48\x86\xF7\x0D\x01\x07\x05", 9))
            return GPGME_DATA_TYPE_CMS_OTHER; /* Digested Data.  */
          if (!memcmp (s, "\x2A\x86\x48\x86\xF7\x0D\x01\x07\x06", 9))
            return GPGME_DATA_TYPE_CMS_OTHER; /* Encrypted Data.  */
        }
      else if (ti.length == 11)
        {
          if (!memcmp (s, "\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x17", 11))
            return GPGME_DATA_TYPE_CMS_ENCRYPTED; /* AuthEnveloped Data.  */
        }
    }


 try_pgp:
  /* Check whether this might be a non-armored PGP message.  We need
     to do this before checking for armor lines, so that we don't get
     fooled by armored messages inside a signed binary PGP message.  */
  if ((data[0] & 0x80))
    {
      /* That might be a binary PGP message.  At least it is not plain
         ASCII.  Of course this might be certain lead-in text of
         armored CMS messages.  However, I am not sure whether this is
         at all defined and in any case it is uncommon.  Thus we don't
         do any further plausibility checks but stupidly assume no CMS
         armored data will follow.  */
      return pgp_binary_detection (data, datalen);
    }

  /* Now check whether there are armor lines.  */
  for (s = data; s && *s; s = (*s=='\n')?(s+1):((s=strchr (s,'\n'))?(s+1):s))
    {
      if (!strncmp (s, "-----BEGIN ", 11))
        {
          if (!strncmp (s+11, "SIGNED ", 7))
            return GPGME_DATA_TYPE_CMS_SIGNED;
          if (!strncmp (s+11, "ENCRYPTED ", 10))
            return GPGME_DATA_TYPE_CMS_ENCRYPTED;
          if (!strncmp (s+11, "PGP ", 4))
            {
              if (!strncmp (s+15, "SIGNATURE", 9))
                return GPGME_DATA_TYPE_PGP_SIGNATURE;
              if (!strncmp (s+15, "SIGNED MESSAGE", 14))
                return GPGME_DATA_TYPE_PGP_SIGNED;
              if (!strncmp (s+15, "PUBLIC KEY BLOCK", 16))
                return GPGME_DATA_TYPE_PGP_KEY;
              if (!strncmp (s+15, "PRIVATE KEY BLOCK", 17))
                return GPGME_DATA_TYPE_PGP_KEY;
              if (!strncmp (s+15, "SECRET KEY BLOCK", 16))
                return GPGME_DATA_TYPE_PGP_KEY;
              if (!strncmp (s+15, "ARMORED FILE", 12))
                return GPGME_DATA_TYPE_UNKNOWN;

              return inspect_pgp_message (data);
            }
          if (!strncmp (s+11, "CERTIFICATE", 11))
            return GPGME_DATA_TYPE_X509_CERT;
          if (!strncmp (s+11, "PKCS12", 6))
            return GPGME_DATA_TYPE_PKCS12;
          return GPGME_DATA_TYPE_CMS_OTHER; /* Not PGP, thus we assume CMS.  */
        }
    }

  return GPGME_DATA_TYPE_UNKNOWN;
}


/* Try to detect the type of the data.  Note that this function works
   only on seekable data objects.  The function tries to reset the
   file pointer but there is no guarantee that it will work.

   FIXME: We may want to add internal buffering so that this function
   can be implemented for almost all kind of data objects.
 */
gpgme_data_type_t
gpgme_data_identify (gpgme_data_t dh, int reserved)
{
  gpgme_data_type_t result;
  char *sample;
  int n;
  gpgme_off_t off;

  (void)reserved;

  /* Check whether we can seek the data object.  */
  off = gpgme_data_seek (dh, 0, SEEK_CUR);
  if (off == (gpgme_off_t)(-1))
    return GPGME_DATA_TYPE_INVALID;

  /* Allocate a buffer and read the data. */
  sample = malloc (SAMPLE_SIZE);
  if (!sample)
    return GPGME_DATA_TYPE_INVALID; /* Ooops.  */
  n = gpgme_data_read (dh, sample, SAMPLE_SIZE - 1);
  if (n < 0)
    {
      free (sample);
      return GPGME_DATA_TYPE_INVALID; /* Ooops.  */
    }
  sample[n] = 0;  /* (Required for our string functions.)  */

  result = basic_detection (sample, n);
  free (sample);
  gpgme_data_seek (dh, off, SEEK_SET);

  return result;
}
