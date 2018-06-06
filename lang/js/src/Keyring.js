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
     * @returns {Promise.<Array<GPGME_Key>>}
     *
     */
    getKeys(pattern, prepare_sync){
        return new Promise(function(resolve, reject) {
            let msg = createMessage('keylist');
            if (pattern !== undefined){
                msg.setParameter('keys', pattern);
            }
            msg.setParameter('sigs', true);
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

    // getDefaultKey() Big TODO

    /**
     *
     * @param {String} armored Armored Key block of the Kex(s) to be imported into gnupg
     * @param {Boolean} prepare_sync prepare the keys for synched use (see getKeys()).
     * @returns {Promise<Array<Object>>} An array of objects for the Keys considered.
    *       Key.key The key itself as a GPGME_Key
     *      Key.status String:
     *          'nochange' if the Key was not changed,
     *          'newkey' if the Key was imported in gpg, and did not exist previously,
     *          'change' if the key existed, but details were updated. For details,
     *              Key.changes is available.
     *      Key.changes.userId: Boolean userIds changed
     *      Key.changes.signature: Boolean signatures changed
     *      Key.changes.subkey: Boolean subkeys changed
     * // TODO: not yet implemented: Information about Keys that failed
     *          (e.g. malformed Keys, secretKeys are not accepted)
     */
    importKey(armored, prepare_sync) {
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
                for (var res=0; res < response.result[0].imports.length; res++) {
                    let result = response.result[0].imports[res];
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
                        resolve(resultset);
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

    // generateKey
}
