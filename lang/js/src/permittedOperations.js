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
          data: <Object>
            the properties expected and their type, eg: {'data':'string'}
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
            data: {
                'data': 'string',
                'base64':'boolean'
            }
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
            'base64': {
                allowed: ['boolean']
            }
        },
        answer: {
            type: ['plaintext'],
            data: {
                'data': 'string',
                'base64': 'boolean',
                'mime': 'boolean',
                'signatures': 'object'
            }
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
            data: {
                'data': 'string',
                'base64':'boolean'
            }

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
            'secret': {
                allowed: ['boolean']
            },
            'extern': {
                allowed: ['boolean']
            },
            'local':{
                allowed: ['boolean']
            },
            'locate': {
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
            data: {
                'base64': 'boolean',
                'keys': 'object'
            }
        }
    },

    export: {
        required: {},
        optional: {
            'protocol': {
                allowed: ['string'],
                allowed_data: ['cms', 'openpgp']
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
            data: {
                'data': 'string',
                'base64': 'boolean'
            }
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
            type: [],
            data: {
                'result': 'object'
            }
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
            // 'secret': { not implemented
            //     allowed: ['boolean']
            // }

        },
        answer: {
            data: {
                'success': 'boolean'
            }
        }
    },

    version: {
        required: {},
        optional: {},
        answer: {
            type:  [''],
            data: {
                'gpgme': 'string',
                'info': 'object'
            }
        }
    },

    createkey: {
        pinentry: true,
        required: {
            userid: {
                allowed: ['string']
            }
        },
        optional: {
            algo: {
                allowed: ['string']
            },
            expires: {
                allowed: ['number'],
            }
        },
        answer: {
            type: [''],
            data: {'fingerprint': 'string'}
        }
    },

    verify: {
        required: {
            data: {
                allowed: ['string']
            }
        },
        optional: {
            'protocol': {
                allowed: ['string'],
                allowed_data: ['cms', 'openpgp']
            },
            'signature': {
                allowed: ['string']
            },
            'base64':{
                allowed: ['boolean']
            }
        },
        answer: {
            type: ['plaintext'],
            data:{
                data: 'string',
                base64:'boolean',
                info: 'object'
                // file_name: Optional string of the plaintext file name.
                //  is_mime: Boolean if the messages claims it is MIME.
                // signatures: Array of signatures
            }
        }
    },

    config_opt: {
        required: {
            'component':{
                allowed: ['string'],
                // allowed_data: ['gpg'] // TODO check all available
            },
            'option': {
                allowed: ['string'],
                // allowed_data: ['default-key'] // TODO check all available
            }
        },
        optional: {},
        answer: {
            type: [],
            data: {
                option: 'object'
            }
        }
    }

    /**
     * TBD handling of secrets
     * TBD key modification?
     */

};
