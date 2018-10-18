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
 * License along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1+
 *
 * Author(s):
 *     Maximilian Krambach <mkrambach@intevation.de>
 */

/**
 * @typedef {Object} messageProperty
 * A message Property is defined by it's key.
 * @property {Array<String>} allowed Array of allowed types.
 * Currently accepted values are 'number', 'string', 'boolean'.
 * @property {Boolean} array_allowed If the value can be an array of types
 *      defined in allowed
 * @property {Array<*>} allowed_data (optional) restricts to the given values
  */

/**
 * Definition of the possible interactions with gpgme-json.
 * @param {Object} operation Each operation is named by a key and contains
 * the following properties:
 * @property {messageProperty} required An object with all required parameters
 * @property {messageProperty} optional An object with all optional parameters
 * @property {Boolean} pinentry (optional) If true, a password dialog is
 *      expected, thus a connection tuimeout is not advisable
 * @property {Object} answer The definition on what to expect as answer, if the
 *      answer is not an error
 * @property {Array<String>} answer.type the type(s) as reported by gpgme-json.
 * @property {Object} answer.payload key-value combinations of expected
 * properties of an answer and their type ('boolean', 'string', object), which
 * may need further decoding from base64
 * @property {Object} answer.info key-value combinations of expected
 * properties of an answer and their type ('boolean', 'string', object), which
 * are meant to be data directly sent by gpgme (i.e. user ids)
  @const
*/
export const permittedOperations = {
    encrypt: {
        pinentry: true, // TODO only with signing_keys
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
            },
            'sender': {
                allowed: ['string']
            },
            'file_name': {
                allowed: ['string']
            }
        },
        answer: {
            type: ['ciphertext'],
            payload: {
                'data': 'string'
            },
            info: {
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
            payload: {
                'data': 'string',
            },
            info: {
                'base64': 'boolean',
                'mime': 'boolean',
                'info': 'object',
                'dec_info': 'object'
            }
        }
    },

    sign: {
        pinentry: true,
        required: {
            'data': {
                allowed: ['string'] },
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
            payload: {
                'data': 'string',
            },
            info: {
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
            info: {
                'keys': 'object',
                'base64': 'boolean',
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
            'pkcs12': {
                allowed: ['boolean']
            },
            'with-sec-fprs': {
                allowed: ['boolean']
            }
            // secret: not yet implemented
        },
        answer: {
            type: ['keys'],
            payload: {
                'data': 'string',
            },
            info: {
                'base64': 'boolean',
                'sec-fprs': 'object'
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
            info: {
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
        },
        answer: {
            info: {
                'success': 'boolean'
            }
        }
    },

    version: {
        required: {},
        optional: {},
        answer: {
            type:  [''],
            info: {
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
            info: { 'fingerprint': 'string' }
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
            payload:{
                'data': 'string'
            },
            info: {
                'base64':'boolean',
                'info': 'object'
                // info.file_name: Optional string of the plaintext file name.
                // info.is_mime: Boolean if the messages claims it is MIME.
                // info.signatures: Array of signatures
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
            info: {
                'option': 'object'
            }
        }
    }
};
