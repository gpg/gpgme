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


import { createMessage } from './Message';
import { createKey } from './Key';
import { isFingerprint } from './Helpers';
import { gpgme_error } from './Errors';

/**
 * This class offers access to the gnupg keyring
 */
export class GPGME_Keyring {

    /**
     * Queries Keys (all Keys or a subset) from gnupg.
     *
     * @param {Object} options:
     * @param {String | Array<String>} options.pattern (optional) A pattern to
     * search for in userIds or KeyIds.
     * @param {Boolean} options.prepare_sync (optional) if set to true, most
     * data (with the exception of armored Key blocks) will be cached for the
     * Keys. This enables direct, synchronous use of these properties for
     * all keys. It does not check for changes on the backend. The cached
     * information can be updated with the {@link Key.refresh} method.
     * @param {Boolean} options.search (optional) retrieve Keys from external
     * servers with the method(s) defined in gnupg (e.g. WKD/HKP lookup)
     * @returns {Promise<GPGME_Key[]>}
     * @static
     * @async
     */
    getKeys ({ pattern, prepare_sync = false, search = false } = {}){
        if (typeof arguments[0] !== 'object') {
            return Promise.reject(gpgme_error('PARAM_WRONG'));
        }
        if (arguments.length && typeof arguments[0] !== 'object') {
            return Promise.reject(gpgme_error('PARAM_WRONG'));
        }
        return new Promise(function (resolve, reject) {
            let msg = createMessage('keylist');
            if (pattern) {
                msg.setParameter('keys', pattern);
            }
            msg.setParameter('sigs', true);
            if (search === true){
                msg.setParameter('locate', true);
            }
            msg.post().then(function (result){
                let resultset = [];
                if (result.keys.length === 0){
                    resolve([]);
                } else {
                    let secondrequest;
                    if (prepare_sync === true) {
                        secondrequest = function () {
                            let msg2 = createMessage('keylist');
                            if (pattern){
                                msg2.setParameter('keys', pattern);
                            }
                            msg2.setParameter('secret', true);
                            return msg2.post();
                        };
                    } else {
                        secondrequest = function () {
                            return Promise.resolve(true);
                        };
                    }
                    secondrequest().then(function (answer) {
                        for (let i=0; i < result.keys.length; i++){
                            if (prepare_sync === true){
                                if (answer && answer.keys) {
                                    for (let j=0;
                                        j < answer.keys.length; j++ ){
                                        const a = answer.keys[j];
                                        const b = result.keys[i];
                                        if (
                                            a.fingerprint === b.fingerprint
                                        ) {
                                            if (a.secret === true){
                                                b.hasSecret = true;
                                            } else {
                                                b.hasSecret = false;
                                            }
                                            break;
                                        }
                                    }
                                }
                            }
                            let k = createKey(result.keys[i].fingerprint,
                                !prepare_sync, result.keys[i]);
                            resultset.push(k);
                        }
                        resolve(resultset);
                    }, function (error){
                        reject(error);
                    });
                }
            });
        });
    }

    /**
     * @typedef {Object} exportResult The result of a getKeysArmored
     * operation.
     * @property {String} armored The public Key(s) as armored block. Note
     * that the result is one armored block, and not a block per key.
     * @property {Array<String>} secret_fprs (optional) list of
     * fingerprints for those Keys that also have a secret Key available in
     * gnupg. The secret key will not be exported, but the fingerprint can
     * be used in operations needing a secret key.
     */

    /**
     * Fetches the armored public Key blocks for all Keys matching the
     * pattern (if no pattern is given, fetches all keys known to gnupg).
     * @param {Object} options (optional)
     * @param {String|Array<String>} options.pattern The Pattern to
     * search for
     * @param {Boolean} options.with_secret_fpr also return a list of
     * fingerprints for the keys that have a secret key available
     * @returns {Promise<exportResult>} Object containing the
     * armored Key(s) and additional information.
     * @static
     * @async
     */
    getKeysArmored ({ pattern, with_secret_fpr }) {
        return new Promise(function (resolve, reject) {
            let msg = createMessage('export');
            msg.setParameter('armor', true);
            if (with_secret_fpr === true) {
                msg.setParameter('with-sec-fprs', true);
            }
            if (pattern){
                msg.setParameter('keys', pattern);
            }
            msg.post().then(function (answer){
                const result = { armored: answer.data };
                if (with_secret_fpr === true){
                    if (answer.hasOwnProperty('sec-fprs')){
                        result.secret_fprs = answer['sec-fprs'];
                    } else {
                        result.secret_fprs = [];
                    }
                }
                resolve(result);
            }, function (error){
                reject(error);
            });
        });
    }

    /**
     * Returns the Key used by default in gnupg.
     * (a.k.a. 'primary Key or 'main key').
     * It looks up the gpg configuration if set, or the first key that
     * contains a secret key.
     *
     * @returns {Promise<GPGME_Key>}
     * @async
     * @static
     */
    getDefaultKey (prepare_sync = false) {
        let me = this;
        return new Promise(function (resolve, reject){
            let msg = createMessage('config_opt');
            msg.setParameter('component', 'gpg');
            msg.setParameter('option', 'default-key');
            msg.post().then(function (resp){
                if (resp.option !== undefined
                    && resp.option.hasOwnProperty('value')
                    && resp.option.value.length === 1
                    && resp.option.value[0].hasOwnProperty('string')
                    && typeof (resp.option.value[0].string) === 'string'){
                    me.getKeys({ pattern: resp.option.value[0].string,
                        prepare_sync: true }).then(
                        function (keys){
                            if (keys.length === 1){
                                resolve(keys[0]);
                            } else {
                                reject(gpgme_error('KEY_NO_DEFAULT'));
                            }
                        }, function (error){
                            reject(error);
                        });
                } else {
                    let msg = createMessage('keylist');
                    msg.setParameter('secret', true);
                    msg.post().then(function (result){
                        if (result.keys.length === 0){
                            reject(gpgme_error('KEY_NO_DEFAULT'));
                        } else {
                            for (let i=0; i< result.keys.length; i++ ) {
                                if (
                                    result.keys[i].invalid === false &&
                                    result.keys[i].expired === false &&
                                    result.keys[i].revoked === false &&
                                    result.keys[i].can_sign === true
                                ) {
                                    let k = createKey(
                                        result.keys[i].fingerprint,
                                        !prepare_sync,
                                        result.keys[i]);
                                    resolve(k);
                                    break;
                                } else if (i === result.keys.length - 1){
                                    reject(gpgme_error('KEY_NO_DEFAULT'));
                                }
                            }
                        }
                    }, function (error){
                        reject(error);
                    });
                }
            }, function (error){
                reject(error);
            });
        });
    }

    /**
     * @typedef {Object} importResult The result of a Key update
     * @property {Object} summary Numerical summary of the result. See the
     * feedbackValues variable for available Keys values and the gnupg
     * documentation.
     * https://www.gnupg.org/documentation/manuals/gpgme/Importing-Keys.html
     * for details on their meaning.
     * @property {Array<importedKeyResult>} Keys Array of Object containing
     * GPGME_Keys with additional import information
     *
     */

    /**
     * @typedef {Object} importedKeyResult
     * @property {GPGME_Key} key The resulting key
     * @property {String} status:
     *  'nochange' if the Key was not changed,
     *  'newkey' if the Key was imported in gpg, and did not exist
     *    previously,
     *  'change' if the key existed, but details were updated. For details,
     *    Key.changes is available.
     * @property {Boolean} changes.userId Changes in userIds
     * @property {Boolean} changes.signature Changes in signatures
     * @property {Boolean} changes.subkey Changes in subkeys
     */

    /**
     * Import an armored Key block into gnupg. Note that this currently
     * will not succeed on private Key blocks.
     * @param {String} armored Armored Key block of the Key(s) to be
     * imported into gnupg
     * @param {Boolean} prepare_sync prepare the keys for synched use
     * (see {@link getKeys}).
     * @returns {Promise<importResult>} A summary and Keys considered.
     * @async
     * @static
     */
    importKey (armored, prepare_sync) {
        let feedbackValues = ['considered', 'no_user_id', 'imported',
            'imported_rsa', 'unchanged', 'new_user_ids', 'new_sub_keys',
            'new_signatures', 'new_revocations', 'secret_read',
            'secret_imported', 'secret_unchanged', 'skipped_new_keys',
            'not_imported', 'skipped_v3_keys'];
        if (!armored || typeof (armored) !== 'string'){
            return Promise.reject(gpgme_error('PARAM_WRONG'));
        }
        let me = this;
        return new Promise(function (resolve, reject){
            let msg = createMessage('import');
            msg.setParameter('data', armored);
            msg.post().then(function (response){
                let infos = {};
                let fprs = [];
                let summary = {};
                for (let i=0; i < feedbackValues.length; i++ ){
                    summary[feedbackValues[i]] =
                        response.result[feedbackValues[i]];
                }
                if (!response.result.hasOwnProperty('imports') ||
                    response.result.imports.length === 0
                ){
                    resolve({ Keys:[],summary: summary });
                    return;
                }
                for (let res=0; res<response.result.imports.length; res++){
                    let result = response.result.imports[res];
                    let status = '';
                    if (result.status === 0){
                        status = 'nochange';
                    } else if ((result.status & 1) === 1){
                        status = 'newkey';
                    } else {
                        status = 'change';
                    }
                    let changes = {};
                    changes.userId = (result.status & 2) === 2;
                    changes.signature = (result.status & 4) === 4;
                    changes.subkey = (result.status & 8) === 8;
                    // 16 new secret key: not implemented
                    fprs.push(result.fingerprint);
                    infos[result.fingerprint] = {
                        changes: changes,
                        status: status
                    };
                }
                let resultset = [];
                if (prepare_sync === true){
                    me.getKeys({ pattern: fprs, prepare_sync: true })
                        .then(function (result){
                            for (let i=0; i < result.length; i++) {
                                resultset.push({
                                    key: result[i],
                                    changes:
                                        infos[result[i].fingerprint].changes,
                                    status: infos[result[i].fingerprint].status
                                });
                            }
                            resolve({ Keys:resultset,summary: summary });
                        }, function (error){
                            reject(error);
                        });
                } else {
                    for (let i=0; i < fprs.length; i++) {
                        resultset.push({
                            key: createKey(fprs[i]),
                            changes: infos[fprs[i]].changes,
                            status: infos[fprs[i]].status
                        });
                    }
                    resolve({ Keys:resultset,summary:summary });
                }

            }, function (error){
                reject(error);
            });


        });


    }

    /**
     * Convenience function for deleting a Key. See {@link Key#delete} for
     * further information about the return values.
     * @param {String} fingerprint
     * @returns {Promise<Boolean>}
     * @async
     * @static
     */
    deleteKey (fingerprint){
        if (isFingerprint(fingerprint) === true) {
            let key = createKey(fingerprint);
            return key.delete();
        } else {
            return Promise.reject(gpgme_error('KEY_INVALID'));
        }
    }

    /**
     * Generates a new Key pair directly in gpg, and returns a GPGME_Key
     * representing that Key. Please note that due to security concerns,
     * secret Keys can not be deleted or exported from inside gpgme.js.
     * @param {Object} options
     * @param {String} option.userId The user Id, e.g. 'Foo Bar <foo@bar.baz>'
     * @param {String} option.algo (optional) algorithm (and optionally key
     * size) to be used. See {@link supportedKeyAlgos} below for supported
     * values. If omitted, 'default' is used.
     * @param {Number} option.expires (optional) Expiration time in seconds
     * from now. If not set or set to 0, expiration will be 'never'
     *
     * @return {Promise<Key|GPGME_Error>}
     * @async
     */
    generateKey ({ userId, algo = 'default', expires= 0 } = {}){
        if (typeof userId !== 'string'
            // eslint-disable-next-line no-use-before-define
            || (algo && supportedKeyAlgos.indexOf(algo) < 0 )
            || (!Number.isInteger(expires) || expires < 0 )
        ){
            return Promise.reject(gpgme_error('PARAM_WRONG'));
        }
        // eslint-disable-next-line no-use-before-define
        let me = this;
        return new Promise(function (resolve, reject){
            let msg = createMessage('createkey');
            msg.setParameter('userid', userId);
            msg.setParameter('algo', algo);
            msg.setParameter('expires', expires);
            msg.post().then(function (response){
                me.getKeys({
                    pattern: response.fingerprint,
                    prepare_sync: true
                }).then(function (result){
                    resolve(result);
                }, function (error){
                    reject(error);
                });
            }, function (error) {
                reject(error);
            });
        });
    }
}


/**
 * List of algorithms supported for key generation. Please refer to the gnupg
 * documentation for details
 */
const supportedKeyAlgos = [
    'default', 'future-default',
    'rsa', 'rsa2048', 'rsa3072', 'rsa4096',
    'dsa', 'dsa2048', 'dsa3072', 'dsa4096',
    'elg', 'elg2048', 'elg3072', 'elg4096',
    'ed25519',
    'cv25519',
    'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1',
    'NIST P-256', 'NIST P-384', 'NIST P-521'
];
