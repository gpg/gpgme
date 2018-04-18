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
      required: Array<String>
      optional: Array<String>
      answer: <Object>
          type: <String< The content type of answer expected
          data: Array<String> The payload property of the answer. May be
                partial and in need of concatenation
          params: Array<String> Information that do not change throughout
                the message
          infos: Array<String> arbitrary information that may change
      }
  }
  */

export const permittedOperations = {
    encrypt: {
        required: ['keys', 'data'],
        optional: [
            'protocol',
            'chunksize',
            'base64',
            'mime',
            'armor',
            'always-trust',
            'no-encrypt-to',
            'no-compress',
            'throw-keyids',
            'want-address',
            'wrap'
        ],
        answer: {
            type: ['ciphertext'],
            data: ['data'],
            params: ['base64'],
            infos: []
        }
    },

    decrypt: {
        required: ['data'],
        optional: [
            'protocol',
            'chunksize',
            'base64'
        ],
        answer: {
            type: ['plaintext'],
            data: ['data'],
            params: ['base64', 'mime'],
            infos: ['info']
        }
    }
}
