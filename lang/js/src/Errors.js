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
 * Checks the given error code and returns some information about it's meaning
 * @param {String} code The error code
 * @returns {Object} An object containing string properties code and msg
 * TODO: error-like objects with the code 'GNUPG_ERROR' are errors sent
 * directly by gnupg as answer in Connection.post()
 */
export function GPGMEJS_Error(code = 'GENERIC_ERROR'){
        if (!typeof(code) === 'string'){
            code = 'GENERIC_ERROR';
        }
        let errors = { //TODO: someplace else
            // Connection
            'CONN_NO_CONNECT': {
                msg:'Connection with the nativeMessaging host could not be'
                    + ' established.',
                type: 'error'
            },
            'CONN_EMPTY_GPG_ANSWER':{
                msg: 'The nativeMessaging answer was empty.',
                type: 'error'
            },
            'CONN_TIMEOUT': {
                msg: 'A connection timeout was exceeded.',
                type: 'error'
            },
            'CONN_UNEXPECTED_ANSWER': {
                msg: 'The answer from gnupg was not as expected.',
                type: 'error'
            },
            'CONN_ALREADY_CONNECTED':{
                msg: 'A connection was already established.',
                type: 'warn'
            },
            // Message/Data
            'MSG_INCOMPLETE': {
                msg: 'The Message did not match the minimum requirements for'
                    + ' the interaction.',
                type: 'error'
            },
            'MSG_EMPTY' : {
                msg: 'The Message is empty.',
                type: 'error'
            },
            'MSG_OP_PENDING': {
                msg: 'There is no operation specified yet. The parameter cannot'
                    + ' be set',
                type: 'warning'
            },
            'MSG_WRONG_OP': {
                msg: 'The operation requested could not be found',
                type: 'warning'
            },
            'MSG_NO_KEYS' : {
                msg: 'There were no valid keys provided.',
                type: 'warn'
            },
            'MSG_NOT_A_FPR': {
                msg: 'The String is not an accepted fingerprint',
                type: 'warn'
            },

            // generic
            'PARAM_WRONG':{
                msg: 'invalid parameter was found',
                type: 'error'
            },
            'NOT_IMPLEMENTED': {
                msg: 'A openpgpjs parameter was submitted that is not implemented',
                type: 'error'
            },
            'NOT_YET_IMPLEMENTED': {
                msg: 'Support of this is probable, but it is not implemented yet',
                type: 'error'
            },
            'GENERIC_ERROR': {
                msg: 'Unspecified error',
                type: 'error'
            },
        }
        if (code === 'TODO'){
            alert('TODO_Error!');
        }
        if (errors.hasOwnProperty(code)){
            code = 'GENERIC_ERROR';
        }
        if (error.type === 'error'){
            return {code: 'code',
                    msg: errors[code].msg
                };
        }
        if (error.type === 'warning'){
            console.log(code + ': ' + error[code].msg);
        }
        return undefined;
}
