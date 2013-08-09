/* data-identify.c - Try to identify the data
   Copyright (C) 2013 g10 Code GmbH

   This file is part of GPGME.

   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, see <http://www.gnu.org/licenses/>.
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



/* Note that DATA may be binary but a final nul is required so that
   string operations will find a terminator.

   Returns: GPGME_DATA_TYPE_xxxx */
static gpgme_data_type_t
basic_detection (const char *data, size_t datalen)
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

    Thus we need to read at least 22 bytes, we add 2 bytes to cope with
    length headers stored with 4 bytes.
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
      if (!(ti.cls == ASN1_CLASS_CONTEXT && ti.tag == 0
            && ti.is_cons && ti.length == 3 && n >= ti.length))
        goto try_pgp;

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
      return GPGME_DATA_TYPE_X509_CERT;
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
          if (!memcmp (s, "\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x02", 11))
            return GPGME_DATA_TYPE_CMS_OTHER; /* Auth Data.  */
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
      return GPGME_DATA_TYPE_UNKNOWN;
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
                return GPGME_DATA_TYPE_PGP_SIGNED;
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
              return GPGME_DATA_TYPE_PGP_OTHER; /* PGP MESSAGE */
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
   can be implemented for allmost all kind of data objects.
 */
gpgme_data_type_t
gpgme_data_identify (gpgme_data_t dh, int reserved)
{
  gpgme_data_type_t result;
  char *sample;
  int n;
  gpgme_off_t off;

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
