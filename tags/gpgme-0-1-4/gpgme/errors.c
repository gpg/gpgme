/* Generated automatically by mkerrors */
/* Do not edit! */

#include <stdio.h>
#include "gpgme.h"

/**
 * gpgme_strerror:
 * @err:  Error code 
 * 
 * This function returns a textual representaion of the given
 * errocode. If this is an unknown value, a string with the value
 * is returned (which is hold in a static buffer).
 * 
 * Return value: String with the error description.
 **/
const char *
gpgme_strerror (GpgmeError err)
{
    const char *s;
    static char buf[25];

    switch (err) {
  case GPGME_No_Error: s="No Error"; break;
  case GPGME_General_Error: s="General Error"; break;
  case GPGME_Out_Of_Core: s="Out Of Core"; break;
  case GPGME_Invalid_Value: s="Invalid Value"; break;
  case GPGME_Busy: s="Busy"; break;
  case GPGME_No_Request: s="No Request"; break;
  case GPGME_Exec_Error: s="Exec Error"; break;
  case GPGME_Too_Many_Procs: s="Too Many Procs"; break;
  case GPGME_Pipe_Error: s="Pipe Error"; break;
  case GPGME_No_Recipients: s="No Recipients"; break;
  case GPGME_No_Data: s="No Data"; break;
  case GPGME_Conflict: s="Conflict"; break;
  case GPGME_Not_Implemented: s="Not Implemented"; break;
  case GPGME_Read_Error: s="Read Error"; break;
  case GPGME_Write_Error: s="Write Error"; break;
  case GPGME_Invalid_Type: s="Invalid Type"; break;
  case GPGME_Invalid_Mode: s="Invalid Mode"; break;
  case GPGME_File_Error: s="File Error"; break;
  case GPGME_Decryption_Failed: s="Decryption Failed"; break;
  case GPGME_No_Passphrase: s="No Passphrase"; break;
  case GPGME_Canceled: s="Canceled"; break;
    default:  sprintf (buf, "ec=%d", err ); s=buf; break;
}

return s;
}

