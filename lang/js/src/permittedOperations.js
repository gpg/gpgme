/* gpgme.js - Javascript integration for gpgme
 * Copyright (C) 2018 Bundesamt für Sicherheit in der Informationstechnik
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
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1+
 */

 /**
  * Definition of the possible interactions with gpgme-json.
  * operation: <Object>
      required: Array<Object>
            <String> name The name of the property
            allowed: Array of allowed types. Currently accepted values:
                ['number', 'string', 'boolean', 'Uint8Array']
            array_allowed: Boolean. If the value can be an array of the above
            allowed_data: <Array> If present, restricts to the given value
      optional: Array<Object>
            see 'required', with these parameters not being mandatory for a
            complete message
      pinentry: boolean If a pinentry dialog is expected, and a timeout of
                5000 ms would be too short
      answer: <Object>
          type: <String< The content type of answer expected
          data: Array<String> The payload property of the answer. May be
                partial and in need of concatenation
          params: Array<String> Information that do not change throughout
                the message
          infos: Array<*> arbitrary information that may result in a list
      }
  }
  */

export const permittedOperations = {
    encrypt: {
        required: {
            'keys': {
                allowed: ['string'],
                array_allowed: true
            },
            'data': {
                allowed: ['string', 'Uint8Array']
            }
        },
        optional: {
            'protocol': {
                allowed: ['string'],
                allowed_data: ['cms', 'openpgp']
            },
                'chunksize': {
                    allowed: ['number']
                },
                'base64': {
                    allowed: ['boolean']
                },
                'mime': {
                    allowed: ['boolean']
                },
                'armor': {
                    allowed: ['boolean']
                },
                'always-trust': {
                    allowed: ['boolean']
                },
                'no-encrypt-to': {
                    allowed: ['string'],
                    array_allowed: true
                },
                'no-compress': {
                    allowed: ['boolean']
                },
                'throw-keyids': {
                    allowed: ['boolean']
                },
                'want-address': {
                    allowed: ['boolean']
                },
                'wrap': {
                    allowed: ['boolean']
                },
            },
        answer: {
            type: ['ciphertext'],
            data: ['data'],
            params: ['base64'],
            infos: []
        }
    },

    decrypt: {
        pinentry: true,
        required: {
            'data': {
                allowed: ['string', 'Uint8Array']
            }
        },
        optional: {
            'protocol': {
                allowed: ['string'],
                allowed_data: ['cms', 'openpgp']
            },
            'chunksize': {
                allowed: ['number'],
            },
            'base64': {
                allowed: ['boolean']
            }
        },
        answer: {
            type: ['plaintext'],
            data: ['data'],
            params: ['base64', 'mime'],
            infos: [] // pending. Info about signatures and validity
                    //signature: [{Key Fingerprint, valid boolean}]
        }
    },
    /**
    keyinfo: { // querying the Key's information.
        required: ['fingerprint'],
        anser: {
            type: ['TBD'],
            data: [],
            params: ['hasSecret', 'isRevoked', 'isExpired', 'armored',
                'timestamp', 'expires', 'pubkey_algo'],
            infos: ['subkeys', 'userIds']
    }*/

    /**
    listkeys:{
        optional: ['with-secret', 'pattern'],
    answer: {
        type: ['TBD'], //Array of fingerprints?
        infos: ['TBD'] //the property with infos
    },
    */

    /**
    importkey: {
        required: ['keyarmored'],
        answer: {
            type: ['TBD'],
            infos: [''], // for each key if import was a success, if it was an update
        }
    },
    */

    /**
    deletekey:  {
        required: ['fingerprint'],
        answer: {
            type ['TBD'],
            infos: [''] //success:true? in gpgme, an error NO_ERROR is returned
        }
    }
    */

    /**
     *get armored secret different treatment from keyinfo!
     */

    /**
     * TBD key modification requests?
     */
}
