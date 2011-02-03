/* extra-stati.lst - Extra GnuPG status codes.
   Copyright 2011 g10 Code GmbH

   This file is free software; as a special exception the author gives
   unlimited permission to copy and/or distribute it, with or without
   modifications, as long as this notice is preserved.

   This file is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY, to the extent permitted by law; without even
   the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
   PURPOSE.  */

/* A list of internal status code to be processed by mkstatus.  Those
 * status codes are not part of the API but internally required by
 * gpgme.  We use a second enum type here but make sure that the
 * values don't clash with those of gpgme_status_code_t.
 */

enum
  {
    /* This value is the first used one.  It needs to be larger than
       the last value of gpgme_status_code_t.  There is no need to
       explictly list the values because they are internal only.  */
    _GPGME_STATUS_FIRST_EXTRA = 192,

    GPGME_STATUS_DECRYPTION_INFO,

    _GPGME_STATUS_LAST_EXTRA
  };
