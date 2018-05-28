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

import {createMessage} from './Message'
import {GPGME_Key, createKey} from './Key'
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
        let me = this;
        return new Promise(function(resolve, reject) {
            let msg;
            msg = createMessage('keylist');
            if (pattern && typeof(pattern) === 'string'){
                msg.setParameter('keys', pattern);
            }
            msg.setParameter('sigs', true); //TODO do we need this?
            msg.post().then(function(result){
                let resultset = [];
                let promises = [];
                // TODO check if result.key is not empty
                for (let i=0; i< result.keys.length; i++){
                    let k = createKey(result.keys[i].fingerprint, me);
                    k.setKeyData(result.keys[i]);
                    if (prepare_sync === true){
                        promises.push(k.getArmor());
                        promises.push(k.getHasSecret());
                    }
                    resultset.push(k);
                }
                if (promises.length > 0) {
                    Promise.all(promises).then(function (res){
                        resolve(resultset);
                    }, function(error){
                        reject(error);
                    });
                }
            }, function(error){
                reject(error);
            });
        });
    }
//  TODO:
    // deleteKey(key, include_secret=false)
    // getKeysArmored(pattern) //just dump all armored keys
    // getDefaultKey() Big TODO
    // importKeys(armoredKeys)

};
