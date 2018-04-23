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

// This is a preliminary collection of erors and warnings to be thrown and implemented.

// general idea: if throw , throw the NAME
// return false || 'return' property

//TODO: Connection.NOCONNECT promise
//connection.timeout: Be aware of pinentry

export class GPGMEJS_Error {

    constructor(code = 'GENERIC_ERROR', details){
        let config = { //TODO TEMP
            debug: 'console', // |'alert'
            throw: 'default'  // | 'always' | 'never'
        };
        let errors = { //TODO: someplace else
            //Connection errors
            'ALREADY_CONNECTED':{
                msg: 'The connection was already established. The action would overwrite the context',
                throw: true
            },
            'NO_CONNECT': {
                msg:'Connection with the nativeMessaging host could not be established.',
                throw: true
            },
            'EMPTY_GPG_ANSWER':{
                msg: 'The nativeMesaging answer was empty',
                throw: true
            },
            'TIMEOUT': {
                msg: 'A timeout was exceeded.',
                throw: false
            },

            'UNEXPECTED_ANSWER': {
                msg: 'The answer from gnupg was not as expected',
                throw: true
            },

            // Message/Data Errors

            'NO_KEYS' : {
                msg: 'There were no valid keys provided.',
                throw: true
            },
            'NOT_A_FPR': {
                msg: 'The String is not an accepted fingerprint',
                throw: false
            },
            'MSG_INCOMPLETE': {
                msg: 'The Message did not match the minimum requirements for the interaction',
                throw: true
            },
            'EMPTY_MSG' : {
                msg: 'The Message has no data.',
                throw: true
            },
            'MSG_NODATA':{
                msg: 'The data sent is empty. This may be unintentional.',
                throw: false
            },
            'MSG_OP_PENDING': {
                msg: 'There is no operation specified yet. The parameter cannot be set',
                throw: false
            },
            'WRONG_OP': {
                msg: "The operation requested could not be found",
                throw: true
            },

            //generic errors

            'WRONGPARAM':{
                msg: 'invalid parameter was found',
                throw: true
            },
            'WRONGTYPE':{
                msg: 'invalid parameter type was found',
                throw: true
            },
            'NOT_IMPLEMENTED': {
                msg: 'A openpgpjs parameter was submitted that is not implemented',
                throw: true
            },
            'GENERIC_ERROR': {
                msg: 'Unspecified error',
                throw: true
            },

            // hopefully temporary errors

            'NOT_YET_IMPLEMENTED': {
                msg: 'Support of this is probable, but it is not implemented yet',
                throw: false
            }
        }
        if (!errors.hasOwnProperty(code)){
            throw('GENERIC_ERROR');
        }
        let msg = code;
        if (errors[code].msg !== undefined){
            msg = msg + ': ' + errors[code].msg;
        }
        if (details){
            msg = msg + ' ' + details;
        }
        if (config.debug === 'console'){
            console.log(msg);
        } else if (config.debug === 'alert'){
            alert(msg);
        }
        switch (config.throw) {
            case 'default':
                if (errors[code].throw === true){
                    throw(code);
                }
                break;
            case 'always':
                throw(code);
                break;

            case 'never':
                break;
            default:
                throw('GENERIC_ERROR');
        }
    }
}
