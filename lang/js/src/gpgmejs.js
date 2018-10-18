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


import { GPGME_Message, createMessage } from './Message';
import { toKeyIdArray } from './Helpers';
import { gpgme_error } from './Errors';
import { GPGME_Keyring } from './Keyring';
import { createSignature } from './Signature';

/**
 * @typedef {Object} decrypt_result
 * @property {String|Uint8Array} data The decrypted data.
 * @property {String} format Indicating how the data was converted after being
 * received from gpgme:
 * <pre>
 *      'ascii': Data was ascii-encoded and no further processed
 *      'string': Data was decoded into an utf-8 string,
 *      'base64': Data was not processed and is a base64 string
 *      'uint8': data was turned into a Uint8Array
 * </pre>
 * @property {Boolean} is_mime (optional) the data claims to be a MIME object.
 * @property {String} file_name (optional) the original file name
 * @property {signatureDetails} signatures Verification details for
 * signatures
 */

/**
 * @typedef {Object} signatureDetails
 * @property {Boolean} all_valid Quick summary. True if all signatures are
 * fully valid according to gnupg.
 * @property {Number} count Number of signatures parsed.
 * @property {Number} failures Number of signatures not passing as valid. This
 * may imply bad signatures, or signatures with e.g. the public Key not being
 * available.
 * @property {GPGME_Signature[]} signatures.good Array of all signatures
 * considered valid.
 * @property {GPGME_Signature[]} signatures.bad All invalid signatures.
 */

/**
 * @typedef {Object} encrypt_result The result of an encrypt operation,
 * containing the encrypted data and some additional information.
 * @property {String} data The encrypted message.
 * @property {String} format Indicating how the data was converted after being
 *  received from gpgme.
 * <pre>
 *      'ascii': Data was ascii-encoded and no further processed
 *      'string': Data was decoded into an utf-8 string,
 *      'base64': Data was not processed and is a base64 string
 *      'uint8': Data was turned into a Uint8Array
 * </pre>
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
 * @property {String} signature The detached signature (only present in in
 * detached mode)
 */

/** @typedef {Object} verifyResult The result of a verification
 * @property {Boolean} data: The verified data
 * @property {Boolean} is_mime (optional) the data claims to be a MIME
 * object.
 * @property {signatureDetails} signatures Verification details for
 * signatures
 */

/**
 * The main entry point for gpgme.js.
 * @class
 */
export class GpgME {

    constructor (){
        this._Keyring = null;
    }

    set Keyring (keyring){
        if (keyring && keyring instanceof GPGME_Keyring){
            this._Keyring = keyring;
        }
    }

    /**
     * Accesses the {@link GPGME_Keyring}. From the Keyring, all Keys can be
     * accessed.
     */
    get Keyring (){
        if (!this._Keyring){
            this._Keyring = new GPGME_Keyring;
        }
        return this._Keyring;
    }

    /**
     * Encrypt data for the recipients specified in publicKeys. If privateKeys
     * are submitted, the data will be signed by those Keys.
     * @param {Object} options
     * @param {String|Object} options.data text/data to be encrypted as String.
     * Also accepts Objects with a getText method.
     * @param {inputKeys} options.publicKeys
     * Keys used to encrypt the message
     * @param {inputKeys} options.secretKeys (optional) Keys used to sign the
     * message. If Keys are present, the  operation requested is assumed
     * to be 'encrypt and sign'
     * @param {Boolean} options.base64 (optional, default: false) The data will
     * be interpreted as base64 encoded data.
     * @param {Boolean} options.armor (optional, default: true) Request the
     * output as armored block.
     * @param {Boolean} options.wildcard (optional, default: false) If true,
     * recipient information will not be added to the message.
     * @param {Boolean} options.always_trust (optional, default true) This
     * assumes that used keys are fully trusted. If set to false, encryption to
     * a key not fully trusted in gnupg will fail.
     * @param {String} options.expect (default: 'base64') In case of
     * armored:false, request how to return the binary result.
     * Accepts 'base64' or 'uint8'
     * @param {Object} options.additional use additional valid gpg options as
     * defined in {@link permittedOperations}
     * @returns {Promise<encrypt_result>} Object containing the encrypted
     * message and additional info.
     * @async
     */
    encrypt ({ data, publicKeys, secretKeys, base64 = false, armor = true,
        wildcard, always_trust = true, expect = 'base64',
        additional = {} } = {}){
        if (typeof arguments[0] !== 'object') {
            return Promise.reject(gpgme_error('PARAM_WRONG'));
        }
        if (!data || !publicKeys){
            return Promise.reject(gpgme_error('MSG_INCOMPLETE'));
        }
        let msg = createMessage('encrypt');
        if (msg instanceof Error){
            return Promise.reject(msg);
        }
        if (armor === false){
            msg.setParameter('armor', false);
            if (expect === 'uint8' || expect === 'base64') {
                msg.expected = expect;
            } else {
                return Promise.reject(gpgme_error('PARAM_WRONG'));
            }
        } else if (armor === true) {
            msg.setParameter('armor', true);
        }
        if (base64 === true) {
            msg.setParameter('base64', true);
        }
        if (always_trust === true) {
            msg.setParameter('always-trust', true);
        }
        let pubkeys = toKeyIdArray(publicKeys);
        if (!pubkeys.length) {
            return Promise.reject(gpgme_error('MSG_NO_KEYS'));
        }
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
                try {
                    msg.setParameter(additional_Keys[k],
                        additional[additional_Keys[k]]);
                }
                catch (error){
                    return Promise.reject(error);
                }
            }
        }
        if (msg.isComplete() === true){
            return msg.post();
        } else {
            return Promise.reject(gpgme_error('MSG_INCOMPLETE'));
        }
    }

    /**
    * Decrypts (and verifies, if applicable) a message.
    * @param {Object} options
    * @param {String|Object} options.data text/data to be decrypted. Accepts
    * Strings and Objects with a getText method.
    * @param {Boolean} options.base64 (optional, default: false). Indicate that
    * the input given is base64-encoded binary instead of an armored block in
    * gpg armored form.
    * @param {String} options.expect (optional). By default, the output is
    * expected to be a string compatible with javascript. In cases of binary
    * data the decryption may fail due to encoding problems. For data expected
    * to return as binary data, the decroding after decryption can be bypassed:
    * <pre>
    *   'uint8': Return as Uint8Array
    *   'base64': Return as unprocessed (base64 encoded) string.
    * </pre>
    * @returns {Promise<decrypt_result>} Decrypted Message and information
    * @async
    */
    decrypt ({ data, base64, expect } = {}){
        if (typeof arguments[0] !== 'object') {
            return Promise.reject(gpgme_error('PARAM_WRONG'));
        }
        if (!data){
            return Promise.reject(gpgme_error('MSG_EMPTY'));
        }
        let msg = createMessage('decrypt');

        if (msg instanceof Error){
            return Promise.reject(msg);
        }
        if (base64 === true){
            msg.setParameter('base64', true);
        }
        if (expect === 'base64' || expect === 'uint8'){
            msg.expected = expect;
        }
        putData(msg, data);
        return new Promise(function (resolve, reject){
            msg.post().then(function (result){
                let returnValue = { data: result.data };
                returnValue.format = result.format ? result.format : null;
                if (result.hasOwnProperty('dec_info')){
                    returnValue.is_mime = result.dec_info.is_mime ? true: false;
                    if (result.dec_info.file_name) {
                        returnValue.file_name = result.dec_info.file_name;
                    }
                }
                if (!returnValue.file_name) {
                    returnValue.file_name = null;
                }
                if (result.hasOwnProperty('info')
                    && result.info.hasOwnProperty('signatures')
                    && Array.isArray(result.info.signatures)
                ) {
                    returnValue.signatures = collectSignatures(
                        result.info.signatures);
                }
                if (returnValue.signatures instanceof Error){
                    reject(returnValue.signatures);
                } else {
                    resolve(returnValue);
                }
            }, function (error){
                reject(error);
            });
        });
    }

    /**
     * Sign a Message.
     * @param {Object} options Signing options
     * @param {String|Object} options.data text/data to be signed. Accepts
     * Strings and Objects with a getText method.
     * @param {inputKeys} options.keys The key/keys to use for signing
     * @param {String} options.mode The signing mode. Currently supported:
     * <pre>
     *      'clearsign':The Message is embedded into the signature;
     *      'detached': The signature is stored separately
     * </pre>
     * @param {Boolean} options.base64 input is considered base64
     * @returns {Promise<signResult>}
     * @async
     */
    sign ({ data, keys, mode = 'clearsign', base64 } = {}){
        if (typeof arguments[0] !== 'object') {
            return Promise.reject(gpgme_error('PARAM_WRONG'));
        }
        if (!data){
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

        return new Promise(function (resolve,reject) {
            msg.post().then( function (message) {
                if (mode === 'clearsign'){
                    resolve({
                        data: message.data }
                    );
                } else if (mode === 'detached') {
                    resolve({
                        data: data,
                        signature: message.data
                    });
                }
            }, function (error){
                reject(error);
            });
        });
    }

    /**
     * Verifies data.
     * @param {Object} options
     * @param {String|Object} options.data text/data to be verified. Accepts
     * Strings and Objects with a getText method
     * @param {String} options.signature A detached signature. If not present,
     * opaque mode is assumed
     * @param {Boolean} options.base64 Indicating that data and signature are
     * base64 encoded
     * @returns {Promise<verifyResult>}
     *@async
    */
    verify ({ data, signature, base64 } = {}){
        if (typeof arguments[0] !== 'object') {
            return Promise.reject(gpgme_error('PARAM_WRONG'));
        }
        if (!data){
            return Promise.reject(gpgme_error('PARAM_WRONG'));
        }
        let msg = createMessage('verify');
        let dt = putData(msg, data);
        if (dt instanceof Error){
            return Promise.reject(dt);
        }
        if (signature){
            if (typeof signature !== 'string'){
                return Promise.reject(gpgme_error('PARAM_WRONG'));
            } else {
                msg.setParameter('signature', signature);
            }
        }
        if (base64 === true){
            msg.setParameter('base64', true);
        }
        return new Promise(function (resolve, reject){
            msg.post().then(function (message){
                if (!message.info || !message.info.signatures){
                    reject(gpgme_error('SIG_NO_SIGS'));
                } else {
                    let returnValue = {
                        signatures: collectSignatures(message.info.signatures)
                    };
                    if (returnValue.signatures instanceof Error){
                        reject(returnValue.signatures);
                    } else {
                        returnValue.is_mime = message.info.is_mime? true: false;
                        if (message.info.filename){
                            returnValue.file_name = message.info.filename;
                        }
                        returnValue.data = message.data;
                        resolve(returnValue);
                    }
                }
            }, function (error){
                reject(error);
            });
        });
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
function putData (message, data){
    if (!message || !(message instanceof GPGME_Message)) {
        return gpgme_error('PARAM_WRONG');
    }
    if (!data){
        return gpgme_error('PARAM_WRONG');
    } else if (typeof data === 'string') {
        message.setParameter('data', data);
    } else if (
        (typeof data === 'object') &&
        (typeof data.getText === 'function')
    ){
        let txt = data.getText();
        if (typeof txt === 'string'){
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
 * @private
 */
function collectSignatures (sigs){
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
        if (sigObj instanceof Error) {
            return gpgme_error('SIG_WRONG');
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