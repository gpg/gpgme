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

export class GPGME_Keyring {
    constructor(){
    }

    /**
     * @param {String} pattern (optional) pattern A pattern to search for,
     * in userIds or KeyIds
     * @param {Boolean} prepare_sync (optional, default true) if set to true,
     * Key.armor and Key.hasSecret will be called, so they can be used
     * inmediately. This allows for full synchronous use. If set to false,
     * these will initially only be available as Promises in getArmor() and
     * getHasSecret()
     * @param {Boolean} search (optional) retrieve the Keys from servers with
     * the method(s) defined in gnupg (e.g. WKD/HKP lookup)
     * @returns {Promise.<Array<GPGME_Key>>}
     *
     */
    getKeys(pattern, prepare_sync, search){
        return new Promise(function(resolve, reject) {
            let msg = createMessage('keylist');
            if (pattern !== undefined){
                msg.setParameter('keys', pattern);
            }
            msg.setParameter('sigs', true);
            if (search === true){
                msg.setParameter('locate', true);
            }
            msg.post().then(function(result){
                let resultset = [];
                let promises = [];
                if (result.keys.length === 0){
                    resolve([]);
                } else {
                    for (let i=0; i< result.keys.length; i++){
                        let k = createKey(result.keys[i].fingerprint);
                        k.setKeyData(result.keys[i]);
                        if (prepare_sync === true){
                            promises.push(k.getArmor());
                            promises.push(k.getHasSecret());
                        }
                        resultset.push(k);
                    }
                    if (promises.length > 0) {
                        Promise.all(promises).then(function() {
                            resolve(resultset);
                        }, function(error){
                            reject(error);
                        });
                    } else {
                        resolve(resultset);
                    }
                }
            });
        });
    }

    /**
     * Fetches the armored public Key blocks for all Keys matchin the pattern
     * (if no pattern is given, fetches all known to gnupg)
     * @param {String|Array<String>} pattern (optional)
     * @returns {Promise<String>} Armored Key blocks
     */
    getKeysArmored(pattern) {
        return new Promise(function(resolve, reject) {
            let msg = createMessage('export');
            msg.setParameter('armor', true);
            if (pattern !== undefined){
                msg.setParameter('keys', pattern);
            }
            msg.post().then(function(result){
                resolve(result.data);
            }, function(error){
                reject(error);
            });
        });
    }

    /**
     * Returns the Key to be used by default for signing operations,
     * looking up the gpg configuration, or returning the first key that
     * contains a secret key.
     * @returns {Promise<GPGME_Key>}
     *
     *
     * TODO: getHasSecret always returns false at this moment, so this fucntion
     * still does not fully work as intended.
     * * @async
     */
    getDefaultKey() {
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
                    me.getKeys(response.value.string,true).then(function(keys){
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
    }

    /**
     *
     * @param {String} armored Armored Key block of the Key(s) to be imported
     * into gnupg
     * @param {Boolean} prepare_sync prepare the keys for synched use
     * (see getKeys()).
     *
     * @returns {Promise<Object>} result: A summary and an array of Keys
     * considered
     *
     * @returns result.summary: Numerical summary of the result. See the
     * feedbackValues variable for available values and the gnupg documentation
     * https://www.gnupg.org/documentation/manuals/gpgme/Importing-Keys.html
     * for details on their meaning.
     * @returns {Array<Object>} result.Keys: Array of objects containing:
     * @returns {GPGME_Key} Key.key The resulting key
     * @returns {String} Key.status:
     *      'nochange' if the Key was not changed,
     *      'newkey' if the Key was imported in gpg, and did not exist
     *         previously,
     *      'change' if the key existed, but details were updated. For
     *         details, Key.changes is available.
     * @returns {Boolean} Key.changes.userId: userIds changed
     * @returns {Boolean} Key.changes.signature: signatures changed
     * @returns {Boolean} Key.changes.subkey: subkeys changed
     */
    importKey(armored, prepare_sync) {
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
                                changes: infos[result[i].fingerprint].changes,
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


    }

    deleteKey(fingerprint){
        if (isFingerprint(fingerprint) === true) {
            let key = createKey(fingerprint);
            key.delete();
        }
    }

    /**
     * Generates a new Key pair directly in gpg, and returns a GPGME_Key
     * representing that Key. Please note that due to security concerns, secret
     * Keys can not be _deleted_ from inside gpgmejs.
     *
     * @param {String} userId The user Id, e.g. "Foo Bar <foo@bar.baz>"
     * @param {*} algo (optional) algorithm (and optionally key size to be
     *  used. See {@link supportedKeyAlgos } below for supported values.
     * @param {Date} expires (optional) Expiration date. If not set, expiration
     * will be set to 'never'
     *
     * @return {Promise<Key>}
     */
    generateKey(userId, algo = 'default', expires){
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
                    // TODO make prepare_sync (second parameter) optional here.
                    function(result){
                        resolve(result);
                    }, function(error){
                        reject(error);
                    });
            }, function(error) {
                reject(error);
            });
        });
    }
}

/**
 * A list of algorithms supported for key generation.
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