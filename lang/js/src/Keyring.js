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


import {createMessage} from './Message';
import {createKey} from './Key';
import { isFingerprint } from './Helpers';
import { gpgme_error } from './Errors';

/**
 * This class offers access to the gnupg keyring
 */
export class GPGME_Keyring {
    constructor(){

        /**
         * Queries Keys (all Keys or a subset) from gnupg.
         *
         * @param {String | Array<String>} pattern (optional) A pattern to
         * search for in userIds or KeyIds.
         * @param {Boolean} prepare_sync (optional) if set to true, the
         * 'hasSecret' and 'armored' properties will be fetched for the Keys as
         * well. These require additional calls to gnupg, resulting in a
         * performance hungry operation. Calling them here enables direct,
         * synchronous use of these properties for all keys, without having to
         * resort to a refresh() first.
         * @param {Boolean} search (optional) retrieve Keys from external
         * servers with the method(s) defined in gnupg (e.g. WKD/HKP lookup)
         * @returns {Promise<Array<GPGME_Key>>}
         * @static
         * @async
         */
        this.getKeys = function(pattern, prepare_sync=false, search=false){
            return new Promise(function(resolve, reject) {
                let msg = createMessage('keylist');
                if (pattern !== undefined && pattern !== null){
                    msg.setParameter('keys', pattern);
                }
                msg.setParameter('sigs', true);
                if (search === true){
                    msg.setParameter('locate', true);
                }
                msg.post().then(function(result){
                    let resultset = [];
                    if (result.keys.length === 0){
                        resolve([]);
                    } else {
                        let secondrequest;
                        if (prepare_sync === true) {
                            secondrequest = function() {
                                let msg2 = createMessage('keylist');
                                msg2.setParameter('keys', pattern);
                                msg2.setParameter('secret', true);
                                return msg2.post();
                            };
                        } else {
                            secondrequest = function() {
                                return Promise.resolve(true);
                            };
                        }
                        secondrequest().then(function(answer) {
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
                                        // TODO getArmor() to be used in sync
                                    }
                                }
                                let k = createKey(result.keys[i].fingerprint);
                                k.setKeyData(result.keys[i]);
                                resultset.push(k);
                            }
                            resolve(resultset);
                        }, function(error){
                            reject(error);
                        });
                    }
                });
            });
        };

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
         * @param {String|Array<String>} pattern (optional) The Pattern to
         * search for
         * @param {Boolean} with_secret_fpr (optional) also return a list of
         * fingerprints for the keys that have a secret key available
         * @returns {Promise<exportResult|GPGME_Error>} Object containing the
         * armored Key(s) and additional information.
         * @static
         * @async
         */
        this.getKeysArmored = function(pattern, with_secret_fpr) {
            return new Promise(function(resolve, reject) {
                let msg = createMessage('export');
                msg.setParameter('armor', true);
                if (with_secret_fpr === true) {
                    msg.setParameter('with-sec-fprs', true);
                }
                if (pattern !== undefined && pattern !== null){
                    msg.setParameter('keys', pattern);
                }
                msg.post().then(function(answer){
                    const result = {armored: answer.data};
                    if (with_secret_fpr === true
                        && answer.hasOwnProperty('sec-fprs')
                    ) {
                        result.secret_fprs = answer['sec-fprs'];
                    }
                    resolve(result);
                }, function(error){
                    reject(error);
                });
            });
        };

        /**
         * Returns the Key used by default in gnupg.
         * (a.k.a. 'primary Key or 'main key').
         * It looks up the gpg configuration if set, or the first key that
         * contains a secret key.
         *
         * @returns {Promise<GPGME_Key|GPGME_Error>}
         * @async
         * @static
         */
        this.getDefaultKey = function() {
            let me = this;
            return new Promise(function(resolve, reject){
                let msg = createMessage('config_opt');
                msg.setParameter('component', 'gpg');
                msg.setParameter('option', 'default-key');
                msg.post().then(function(response){
                    if (response.value !== undefined
                        && response.value.hasOwnProperty('string')
                        && typeof(response.value.string) === 'string'
                    ){
                        me.getKeys(response.value.string,true).then(
                            function(keys){
                                if(keys.length === 1){
                                    resolve(keys[0]);
                                } else {
                                    reject(gpgme_error('KEY_NO_DEFAULT'));
                                }
                            }, function(error){
                                reject(error);
                            });
                    } else {
                        // TODO: this is overly 'expensive' in communication
                        // and probably performance, too
                        me.getKeys(null,true).then(function(keys){
                            for (let i=0; i < keys.length; i++){
                                if (keys[i].get('hasSecret') === true){
                                    resolve(keys[i]);
                                    break;
                                }
                                if (i === keys.length -1){
                                    reject(gpgme_error('KEY_NO_DEFAULT'));
                                }
                            }
                        }, function(error){
                            reject(error);
                        });
                    }
                }, function(error){
                    reject(error);
                });
            });
        };

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
        this.importKey = function (armored, prepare_sync) {
            let feedbackValues = ['considered', 'no_user_id', 'imported',
                'imported_rsa', 'unchanged', 'new_user_ids', 'new_sub_keys',
                'new_signatures', 'new_revocations', 'secret_read',
                'secret_imported', 'secret_unchanged', 'skipped_new_keys',
                'not_imported', 'skipped_v3_keys'];
            if (!armored || typeof(armored) !== 'string'){
                return Promise.reject(gpgme_error('PARAM_WRONG'));
            }
            let me = this;
            return new Promise(function(resolve, reject){
                let msg = createMessage('import');
                msg.setParameter('data', armored);
                msg.post().then(function(response){
                    let infos = {};
                    let fprs = [];
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
                        //16 new secret key: not implemented

                        fprs.push(result.fingerprint);
                        infos[result.fingerprint] = {
                            changes: changes,
                            status: status
                        };
                    }
                    let resultset = [];
                    if (prepare_sync === true){
                        me.getKeys(fprs, true).then(function(result){
                            for (let i=0; i < result.length; i++) {
                                resultset.push({
                                    key: result[i],
                                    changes:
                                        infos[result[i].fingerprint].changes,
                                    status: infos[result[i].fingerprint].status
                                });
                            }
                            let summary = {};
                            for (let i=0; i < feedbackValues.length; i++ ){
                                summary[feedbackValues[i]] =
                                    response[feedbackValues[i]];
                            }
                            resolve({
                                Keys:resultset,
                                summary: summary
                            });
                        }, function(error){
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
                        resolve(resultset);
                    }

                }, function(error){
                    reject(error);
                });


            });


        };

        /**
         * Convenience function for deleting a Key. See {@link Key.delete} for
         * further information about the return values.
         * @param {String} fingerprint
         * @returns {Promise<Boolean|GPGME_Error>}
         * @async
         * @static
         */
        this.deleteKey = function(fingerprint){
            if (isFingerprint(fingerprint) === true) {
                let key = createKey(fingerprint);
                return key.delete();
            } else {
                return Promise.reject(gpgme_error('KEY_INVALID'));
            }
        };

        /**
         * Generates a new Key pair directly in gpg, and returns a GPGME_Key
         * representing that Key. Please note that due to security concerns,
         * secret Keys can not be deleted or exported from inside gpgme.js.
         *
         * @param {String} userId The user Id, e.g. 'Foo Bar <foo@bar.baz>'
         * @param {String} algo (optional) algorithm (and optionally key size)
         * to be used. See {@link supportedKeyAlgos} below for supported
         * values.
         * @param {Date} expires (optional) Expiration date. If not set,
         * expiration will be set to 'never'
         *
         * @return {Promise<Key|GPGME_Error>}
         * @async
         */
        this.generateKey = function (userId, algo = 'default', expires){
            if (
                typeof(userId) !== 'string' ||
                supportedKeyAlgos.indexOf(algo) < 0 ||
                (expires && !(expires instanceof Date))
            ){
                return Promise.reject(gpgme_error('PARAM_WRONG'));
            }
            let me = this;
            return new Promise(function(resolve, reject){
                let msg = createMessage('createkey');
                msg.setParameter('userid', userId);
                msg.setParameter('algo', algo );
                if (expires){
                    msg.setParameter('expires',
                        Math.floor(expires.valueOf()/1000));
                }
                msg.post().then(function(response){
                    me.getKeys(response.fingerprint, true).then(
                        // TODO prepare_sync?
                        function(result){
                            resolve(result);
                        }, function(error){
                            reject(error);
                        });
                }, function(error) {
                    reject(error);
                });
            });
        };
    }
}

/**
 * List of algorithms supported for key generation. Please refer to the gnupg
 * documentation for details
 */
const supportedKeyAlgos = [
    'default',
    'rsa', 'rsa2048', 'rsa3072', 'rsa4096',
    'dsa', 'dsa2048', 'dsa3072', 'dsa4096',
    'elg', 'elg2048', 'elg3072', 'elg4096',
    'ed25519',
    'cv25519',
    'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1',
    'NIST P-256', 'NIST P-384', 'NIST P-521'
];