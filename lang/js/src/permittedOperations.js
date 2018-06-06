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
 *
 * Author(s):
 *     Maximilian Krambach <mkrambach@intevation.de>
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
        pinentry: true, //TODO only with signing_keys
        required: {
            'keys': {
                allowed: ['string'],
                array_allowed: true
            },
            'data': {
                allowed: ['string']
            }
        },
        optional: {
            'protocol': {
                allowed: ['string'],
                allowed_data: ['cms', 'openpgp']
            },
            'signing_keys': {
                allowed: ['string'],
                array_allowed: true
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
            }
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
                allowed: ['string']
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
            infos: ['signatures']
        }
    },

    sign: {
        pinentry: true,
        required: {
            'data': {
                allowed: ['string']},
            'keys': {
                allowed: ['string'],
                array_allowed: true
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
            'sender': {
                allowed: ['string'],
            },
            'mode': {
                allowed: ['string'],
                allowed_data: ['detached', 'clearsign']
                // TODO 'opaque' is not used, but available on native app
            },
            'base64': {
                allowed: ['boolean']
            },
            'armor': {
                allowed: ['boolean']
            },
        },
        answer: {
            type: ['signature', 'ciphertext'],
            data: ['data'], // Unless armor mode is used a Base64 encoded binary
            // signature.  In armor mode a string with an armored
            // OpenPGP or a PEM message.
            params: ['base64']
        }
    },

    // note: For the meaning of the optional keylist flags, refer to
    // https://www.gnupg.org/documentation/manuals/gpgme/Key-Listing-Mode.html
    keylist:{
        required: {},

        optional: {
            'protocol': {
                allowed: ['string'],
                allowed_data: ['cms', 'openpgp']
            },
            'chunksize': {
                allowed: ['number'],
            },
            'secret': {
                allowed: ['boolean']
            },
            'extern': {
                allowed: ['boolean']
            },
            'local':{
                allowed: ['boolean']
            },
            'sigs':{
                allowed: ['boolean']
            },
            'notations':{
                allowed: ['boolean']
            },
            'tofu': {
                allowed: ['boolean']
            },
            'ephemeral': {
                allowed: ['boolean']
            },
            'validate': {
                allowed: ['boolean']
            },
            'keys': {
                allowed: ['string'],
                array_allowed: true
            }
        },
        answer: {
            type: ['keys'],
            data: [],
            params: ['base64'],
            infos: ['keys']
        }
    },

    export: {
        required: {},
        optional: {
            'protocol': {
                allowed: ['string'],
                allowed_data: ['cms', 'openpgp']
            },
            'chunksize': {
                allowed: ['number'],
            },
            'keys': {
                allowed: ['string'],
                array_allowed: true
            },
            'armor': {
                allowed: ['boolean']
            },
            'extern': {
                allowed: ['boolean']
            },
            'minimal': {
                allowed: ['boolean']
            },
            'raw': {
                allowed: ['boolean']
            },
            'pkcs12':{
                allowed: ['boolean']
            }
            // secret: not yet implemented
        },
        answer: {
            type: ['keys'],
            data: ['data'],
            params: ['base64']
        }
    },

    import: {
        required: {
            'data': {
                allowed: ['string']
            }
        },
        optional: {
            'protocol': {
                allowed: ['string'],
                allowed_data: ['cms', 'openpgp']
            },
            'base64': {
                allowed: ['boolean']
            },
        },
        answer: {
            infos: ['result'],
            type: [],
            data: [],
            params: []
        }
    },

    delete: {
        pinentry: true,
        required:{
            'key': {
                allowed: ['string']
            }
        },
        optional: {
            'protocol': {
                allowed: ['string'],
                allowed_data: ['cms', 'openpgp']
            },
            // 'secret': { not yet implemented
            //     allowed: ['boolean']
            // }

        },
        answer: {
            data: [],
            params:['success'],
            infos: []
        }
    },

    version: {
        required: {},
        optional: {},
        answer: {
            type:  [''],
            data: ['gpgme'],
            infos: ['info'],
            params:[]
        }
    }

    /**
     * TBD handling of secrets
     * TBD key modification?
     * TBD: key generation
     */

};
