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
 * Listing of all possible error codes and messages of a {@link GPGME_Error}.
 */
export const err_list = {
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
    'CONN_NO_CONFIG':{
        msg: 'The browser does not recognize the nativeMessaging host.',
        type: 'error'
    },
    'CONN_NATIVEMESSAGE':{
        msg: 'The native messaging was not successful.',
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
        type: 'warning'
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
    'MSG_WRONG_OP': {
        msg: 'The operation requested could not be found',
        type: 'error'
    },
    'MSG_NO_KEYS' : {
        msg: 'There were no valid keys provided.',
        type: 'warning'
    },
    'MSG_NOT_A_FPR': {
        msg: 'The String is not an accepted fingerprint',
        type: 'warning'
    },
    'KEY_INVALID': {
        msg:'Key object is invalid',
        type: 'error'
    },
    'KEY_NOKEY': {
        msg:'This key does not exist in GPG',
        type: 'error'
    },
    'KEY_NO_INIT': {
        msg:'This property has not been retrieved yet from GPG',
        type: 'error'
    },
    'KEY_ASYNC_ONLY': {
        msg: 'This property cannot be used in synchronous calls',
        type: 'error'
    },
    'KEY_NO_DEFAULT': {
        msg:'A default key could not be established. Please check yout gpg ' +
            'configuration',
        type: 'error'
    },
    'SIG_WRONG': {
        msg:'A malformed signature was created',
        type: 'error'
    },
    'SIG_NO_SIGS': {
        msg:'There were no signatures found',
        type: 'error'
    },
    // generic
    'PARAM_WRONG':{
        msg: 'Invalid parameter was found',
        type: 'error'
    },
    'DECODE_FAIL': {
        msg: 'Decoding failed due to unexpected data',
        type: 'error'
    },
    'PARAM_IGNORED': {
        msg: 'An parameter was set that has no effect in gpgmejs',
        type: 'warning'
    },
    'GENERIC_ERROR': {
        msg: 'Unspecified error',
        type: 'error'
    }
};

/**
 * Checks the given error code and returns an {@link GPGME_Error} error object
 * with some information about meaning and origin
 * @param {String} code Error code as defined in {@link err_list}.
 * @param {String} info Possible additional error message to pass through.
 * Currently used for errors sent as answer by gnupg via a native Message port
 * @returns {GPGME_Error}
 */
export function gpgme_error (code = 'GENERIC_ERROR', info){
    if (err_list.hasOwnProperty(code)){
        if (err_list[code].type === 'error'){
            return new GPGME_Error(code);
        }
        if (err_list[code].type === 'warning'){
            // eslint-disable-next-line no-console
            // console.warn(code + ': ' + err_list[code].msg);
        }
        return null;
    } else if (code === 'GNUPG_ERROR'){
        return new GPGME_Error(code, info);
    }
    else {
        return new GPGME_Error('GENERIC_ERROR');
    }
}

/**
 * An error class with additional info about the origin of the error, as string
 * It is created by {@link gpgme_error}, and its' codes are defined in
 * {@link err_list}.
 *
 * @property {String} code Short description of origin and type of the error
 * @property {String} msg Additional info
 * @protected
 * @class
 * @extends Error
 */
class GPGME_Error extends Error{
    constructor (code = 'GENERIC_ERROR', msg=''){
        const verboseErrors = ['GNUPG_ERROR', 'CONN_NATIVEMESSAGE'];
        if (verboseErrors.includes(code) && typeof (msg) === 'string'){
            super(msg);
        } else if (err_list.hasOwnProperty(code)){
            if (msg){
                super(err_list[code].msg + '--' + msg);
            } else {
                super(err_list[code].msg);
            }
        } else {
            super(err_list['GENERIC_ERROR'].msg);
        }
        this._code = code;
    }

    get code (){
        return this._code;
    }
}