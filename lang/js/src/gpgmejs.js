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


import { GPGME_Message, createMessage } from './Message';
import { toKeyIdArray } from './Helpers';
import { gpgme_error } from './Errors';
import { GPGME_Keyring } from './Keyring';
import { createSignature } from './Signature';

/**
 * @typedef {Object} decrypt_result
 * @property {String} data The decrypted data
 * @property {Boolean} base64 indicating whether data is base64 encoded.
 * @property {Boolean} is_mime (optional) the data claims to be a MIME
 * object.
 * @property {String} file_name (optional) the original file name
 * @property {signatureDetails} signatures Verification details for
 * signatures
 */

/**
 * @typedef {Object} signatureDetails
 * @property {Boolean} all_valid Summary if all signatures are fully valid
 * @property {Number} count Number of signatures found
 * @property {Number} failures Number of invalid signatures
 * @property {Array<GPGME_Signature>} signatures.good All valid signatures
 * @property {Array<GPGME_Signature>} signatures.bad All invalid signatures
 */

/**
 * @typedef {Object} encrypt_result The result of an encrypt operation
 * @property {String} data The encrypted message
 * @property {Boolean} base64 Indicating whether data is base64 encoded.
 */

/**
 * @typedef { GPGME_Key | String | Object } inputKeys
 * Accepts different identifiers of a gnupg Key that can be parsed by
 * {@link toKeyIdArray}. Expected inputs are: One or an array of
 * GPGME_Keys; one or an array of fingerprint strings; one or an array of
 * openpgpjs Key objects.
 */

/**
 * @typedef {Object} signResult The result of a signing operation
 * @property {String} data The resulting data. Includes the signature in
 *  clearsign mode
 * @property {String} signature The detached signature (if in detached mode)
 */

/** @typedef {Object} verifyResult The result of a verification
 * @property {Boolean} data: The verified data
 * @property {Boolean} is_mime (optional) the data claims to be a MIME
 * object.
 * @property {String} file_name (optional) the original file name
 * @property {signatureDetails} signatures Verification details for
 * signatures
 */

/**
 * The main entry point for gpgme.js.
 * @class
 */
export class GpgME {

    constructor(){
        let _Keyring = null;

        /**
         * Sets a new Keyring to be used
         * @param {GPGME_Keyring} keyring
         */
        this.setKeyring = function(keyring){
            if (keyring && keyring instanceof GPGME_Keyring){
                _Keyring = keyring;
            }
        };

        /**
         * Accesses the {@link GPGME_Keyring}.
         */
        this.getKeyring = function(){
            if (!_Keyring){
                _Keyring = Object.freeze(new GPGME_Keyring);
            }
            return _Keyring;
        };

        /**
         * Encrypt (and optionally sign) data
         * @param {String|Object} data text/data to be encrypted as String. Also
         * accepts Objects with a getText method
         * @param {inputKeys} publicKeys
         * Keys used to encrypt the message
         * @param {inputKeys} secretKeys (optional) Keys used to sign the
         * message. If Keys are present, the  operation requested is assumed
         * to be 'encrypt and sign'
         * @param {Boolean} base64 (optional) The data will be interpreted as
         * base64 encoded data.
         * @param {Boolean} armor (optional) Request the output as armored
         * block.
         * @param {Boolean} wildcard (optional) If true, recipient information
         * will not be added to the message.
         * @param {Object} additional use additional valid gpg options as
         * defined in {@link permittedOperations}
         * @returns {Promise<encrypt_result>} Object containing the encrypted
         * message and additional info.
         * @async
         */
        this.encrypt = function (data, publicKeys, secretKeys, base64=false,
            armor=true, wildcard=false, additional = {}
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
            if (msg.isComplete() === true){
                return msg.post();
            } else {
                return Promise.reject(gpgme_error('MSG_INCOMPLETE'));
            }
        };

        /**
        * Decrypts a Message
        * @param {String|Object} data text/data to be decrypted. Accepts
        * Strings and Objects with a getText method
        * @param {Boolean} base64 (optional) false if the data is an armored
        * block, true if it is base64 encoded binary data
        * @returns {Promise<decrypt_result>} Decrypted Message and information
        * @async
        */
        this.decrypt = function (data, base64=false){
            if (data === undefined){
                return Promise.reject(gpgme_error('MSG_EMPTY'));
            }
            let msg = createMessage('decrypt');

            if (msg instanceof Error){
                return Promise.reject(msg);
            }
            if (base64 === true){
                msg.setParameter('base64', true);
            }
            putData(msg, data);
            if (base64 === true){
                msg.setParameter('base64', true);
            }
            return new Promise(function(resolve, reject){
                msg.post().then(function(result){
                    let _result = {data: result.data};
                    _result.base64 = result.base64 ? true: false;
                    _result.is_mime = result.mime ? true: false;
                    if (result.file_name){
                        _result.file_name = result.file_name;
                    }
                    if (
                        result.hasOwnProperty('signatures') &&
                        Array.isArray(result.signatures)
                    ) {
                        _result.signatures = collectSignatures(
                            result.signatures);
                    }
                    resolve(_result);
                }, function(error){
                    reject(error);
                });
            });
        };

        /**
         * Sign a Message
         * @param {String|Object} data text/data to be signed. Accepts Strings
         * and Objects with a getText method.
         * @param {inputKeys} keys The key/keys to use for signing
         * @param {String} mode The signing mode. Currently supported:
         *  'clearsign':The Message is embedded into the signature;
         *  'detached': The signature is stored separately
         * @param {Boolean} base64 input is considered base64
         * @returns {Promise<signResult>}
         * @async
         */
        this.sign = function (data, keys, mode='clearsign', base64=false) {
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
                    msg.setExpect('base64');
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
        };

        /**
         * Verifies data.
         * @param {String|Object} data text/data to be verified. Accepts Strings
         * and Objects with a getText method
         * @param {String} (optional) A detached signature. If not present,
         * opaque mode is assumed
         * @param {Boolean} (optional) Data and signature are base64 encoded
         * @returns {Promise<verifyResult>}
         *@async
        */
        this.verify= function (data, signature, base64 = false){
            let msg = createMessage('verify');
            let dt = putData(msg, data);
            if (dt instanceof Error){
                return Promise.reject(dt);
            }
            if (signature){
                if (typeof(signature)!== 'string'){
                    return Promise.reject(gpgme_error('PARAM_WRONG'));
                } else {
                    msg.setParameter('signature', signature);
                }
            }
            if (base64 === true){
                msg.setParameter('base64', true);
            }
            return new Promise(function(resolve, reject){
                msg.post().then(function (message){
                    if (!message.info || !message.info.signatures){
                        reject(gpgme_error('SIG_NO_SIGS'));
                    } else {
                        let _result = collectSignatures(
                            message.info.signatures);
                        _result.is_mime = message.info.is_mime? true: false;
                        if (message.info.filename){
                            _result.file_name = message.info.filename;
                        }
                        _result.data = message.data;
                        resolve(_result);
                    }
                }, function(error){
                    reject(error);
                });
            });
        };
    }

    /**
     * setter for {@link setKeyring}.
     * @param {GPGME_Keyring} keyring A Keyring to use
     */
    set Keyring(keyring){
        this.setKeyring(keyring);
    }

    /**
     * Accesses the {@link GPGME_Keyring}.
     */
    get Keyring(){
        return this.getKeyring();
    }
}

/**
 * Sets the data of the message, setting flags according on the data type
 * @param {GPGME_Message} message The message where this data will be set
 * @param { String| Object } data The data to enter. Expects either a string of
 * data, or an object with a getText method
 * @returns {undefined| GPGME_Error} Error if not successful, nothing otherwise
 * @private
 */
function putData(message, data){
    if (!message || !(message instanceof GPGME_Message)) {
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

/**
 * Parses, validates and converts incoming objects into signatures.
 * @param {Array<Object>} sigs
 * @returns {signatureDetails} Details about the signatures
 */
function collectSignatures(sigs){
    if (!Array.isArray(sigs)){
        return gpgme_error('SIG_NO_SIGS');
    }
    let summary = {
        all_valid: false,
        count: sigs.length,
        failures: 0,
        signatures: {
            good: [],
            bad: [],
        }
    };
    for (let i=0; i< sigs.length; i++){
        let sigObj = createSignature(sigs[i]);
        if (sigObj instanceof Error){
            return gpgme_error(sigObj);
        }
        if (sigObj.valid !== true){
            summary.failures += 1;
            summary.signatures.bad.push(sigObj);
        } else {
            summary.signatures.good.push(sigObj);
        }
    }
    if (summary.failures === 0){
        summary.all_valid = true;
    }
    return summary;
}