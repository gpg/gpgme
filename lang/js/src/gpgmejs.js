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


import {GPGME_Message, createMessage} from './Message';
import {toKeyIdArray} from './Helpers';
import { gpgme_error } from './Errors';
import { GPGME_Keyring } from './Keyring';

export class GpgME {
    /**
     * initializes GpgME by opening a nativeMessaging port
     */
    constructor(){
    }

    set Keyring(keyring){
        if (keyring && keyring instanceof GPGME_Keyring){
            this._Keyring = keyring;
        }
    }

    get Keyring(){
        if (!this._Keyring){
            this._Keyring = new GPGME_Keyring;
        }
        return this._Keyring;
    }

    /**
     * Encrypt (and optionally sign) a Message
     * @param {String|Object} data text/data to be encrypted as String. Also
     * accepts Objects with a getText method
     * @param  {GPGME_Key|String|Array<String>|Array<GPGME_Key>} publicKeys
     * Keys used to encrypt the message
     * @param  {GPGME_Key|String|Array<String>|Array<GPGME_Key>} secretKeys
     * (optional) Keys used to sign the message
     * @param {Boolean} base64 (optional) The data will be interpreted as
     * base64 encoded data
     * @param {Boolean} armor (optional) Request the output as armored block
     * @param {Boolean} wildcard (optional) If true, recipient information will
     *  not be added to the message
     * @param {Object} additional use additional gpg options
     * (refer to src/permittedOperations)
     * @returns {Promise<Object>} Encrypted message:
     *   data: The encrypted message
     *   base64: Boolean indicating whether data is base64 encoded.
     * @async
     */
    encrypt(data, publicKeys, secretKeys, base64=false, armor=true,
        wildcard=false, additional = {}
    ){
        let msg = createMessage('encrypt');
        if (msg instanceof Error){
            return Promise.reject(msg);
        }
        msg.setParameter('armor', armor);
        msg.setParameter('always-trust', true);
        if (base64 === true) {
            msg.setParameter('base64', true);
        }
        let pubkeys = toKeyIdArray(publicKeys);
        msg.setParameter('keys', pubkeys);
        let sigkeys = toKeyIdArray(secretKeys);
        if (sigkeys.length > 0) {
            msg.setParameter('signing_keys', sigkeys);
        }
        putData(msg, data);
        if (wildcard === true){
            msg.setParameter('throw-keyids', true);
        }
        if (additional){
            let additional_Keys = Object.keys(additional);
            for (let k = 0; k < additional_Keys.length; k++) {
                msg.setParameter(additional_Keys[k],
                    additional[additional_Keys[k]]);
            }
        }
        if (msg.isComplete === true){
            return msg.post();
        } else {
            return Promise.reject(gpgme_error('MSG_INCOMPLETE'));
        }
    }

    /**
    * Decrypt a Message
    * @param {String|Object} data text/data to be decrypted. Accepts Strings
    *  and Objects with a getText method
    * @returns {Promise<Object>} decrypted message:
        data:   The decrypted data.
        base64: Boolean indicating whether data is base64 encoded.
        mime:   A Boolean indicating whether the data is a MIME object.
        signatures: Array of signature Objects TODO not yet implemented.
            // should be an object that can tell if all signatures are valid.
    * @async
    */
    decrypt(data){
        if (data === undefined){
            return Promise.reject(gpgme_error('MSG_EMPTY'));
        }
        let msg = createMessage('decrypt');

        if (msg instanceof Error){
            return Promise.reject(msg);
        }
        putData(msg, data);
        return msg.post();
    }

    /**
     * Sign a Message
     * @param {String|Object} data text/data to be decrypted. Accepts Strings
     * and Objects with a gettext methos
     * @param {GPGME_Key|String|Array<String>|Array<GPGME_Key>} keys The
     * key/keys to use for signing
     * @param {*} mode The signing mode. Currently supported:
     *      'clearsign': (default) The Message is embedded into the signature
     *      'detached': The signature is stored separately
     * @param {*} base64 input is considered base64
     * @returns {Promise<Object>}
     *    data: The resulting data. Includes the signature in clearsign mode
     *    signature: The detached signature (if in detached mode)
     * @async
     */
    sign(data, keys, mode='clearsign', base64=false) {
        if (data === undefined){
            return Promise.reject(gpgme_error('MSG_EMPTY'));
        }
        let key_arr = toKeyIdArray(keys);
        if (key_arr.length === 0){
            return Promise.reject(gpgme_error('MSG_NO_KEYS'));
        }
        let msg = createMessage('sign');

        msg.setParameter('keys', key_arr);
        if (base64 === true){
            msg.setParameter('base64', true);
        }
        msg.setParameter('mode', mode);
        putData(msg, data);
        return new Promise(function(resolve,reject) {
            if (mode ==='detached'){
                msg.expect= 'base64';
            }
            msg.post().then( function(message) {
                if (mode === 'clearsign'){
                    resolve({
                        data: message.data}
                    );
                } else if (mode === 'detached') {
                    resolve({
                        data: data,
                        signature: message.data
                    });
                }
            }, function(error){
                reject(error);
            });
        });
    }
}

/**
 * Sets the data of the message, setting flags according on the data type
 * @param {GPGME_Message} message The message where this data will be set
 * @param {*} data The data to enter
 */
function putData(message, data){
    if (!message || !(message instanceof GPGME_Message) ) {
        return gpgme_error('PARAM_WRONG');
    }
    if (!data){
        return gpgme_error('PARAM_WRONG');
    } else if (typeof(data) === 'string') {
        message.setParameter('data', data);
    } else if (
        typeof(data) === 'object' &&
        typeof(data.getText) === 'function'
    ){
        let txt = data.getText();
        if (typeof(txt) === 'string'){
            message.setParameter('data', txt);
        } else {
            return gpgme_error('PARAM_WRONG');
        }

    } else {
        return gpgme_error('PARAM_WRONG');
    }
}
