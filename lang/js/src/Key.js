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

import { isFingerprint, isLongId } from './Helpers';
import { gpgme_error } from './Errors';
import { createMessage } from './Message';

/**
 * Validates the fingerprint.
 * @param {String} fingerprint
 */
export function createKey(fingerprint){
    if (!isFingerprint(fingerprint)){
        return gpgme_error('PARAM_WRONG');
    }
    else return new GPGME_Key(fingerprint);
}

/**
 * Representing the Keys as stored in GPG
 * It allows to query almost all information defined in gpgme Key Objects
 * Refer to validKeyProperties for available information, and the gpgme
 * documentation on their meaning
 * (https://www.gnupg.org/documentation/manuals/gpgme/Key-objects.html)
 *
 */
export class GPGME_Key {

    constructor(fingerprint){
        this.fingerprint = fingerprint;
    }

    set fingerprint(fpr){
        if (isFingerprint(fpr) === true) {
            if (this._data === undefined) {
                this._data = {fingerprint:  fpr};
            } else {
                if (this._data.fingerprint === undefined){
                    this._data.fingerprint = fpr;
                }
            }
        }
    }

    get fingerprint(){
        if (!this._data || !this._data.fingerprint){
            return gpgme_error('KEY_INVALID');
        }
        return this._data.fingerprint;
    }

    /**
     *
     * @param {Object} data Bulk set data for this key, with the Object as sent
     * by gpgme-json.
     * @returns {GPGME_Key|GPGME_Error} The Key object itself after values have
     * been set
     */
    setKeyData(data){
        if (this._data === undefined) {
            this._data = {};
        }
        if (
            typeof(data) !== 'object') {
            return gpgme_error('KEY_INVALID');
        }
        if (!this._data.fingerprint && isFingerprint(data.fingerprint)){
            if (data.fingerprint !== this.fingerprint){
                return gpgme_error('KEY_INVALID');
            }
            this._data.fingerprint = data.fingerprint;
        } else if (this._data.fingerprint !== data.fingerprint){
            return gpgme_error('KEY_INVALID');
        }
        let dataKeys = Object.keys(data);
        for (let i=0; i< dataKeys.length; i++){
            if (!validKeyProperties.hasOwnProperty(dataKeys[i])){
                return gpgme_error('KEY_INVALID');
            }
            if (validKeyProperties[dataKeys[i]](data[dataKeys[i]]) !== true ){
                return gpgme_error('KEY_INVALID');
            }
            switch (dataKeys[i]){
            case 'subkeys':
                this._data.subkeys = [];
                for (let i=0; i< data.subkeys.length; i++) {
                    this._data.subkeys.push(
                        new GPGME_Subkey(data.subkeys[i]));
                }
                break;
            case 'userids':
                this._data.userids = [];
                for (let i=0; i< data.userids.length; i++) {
                    this._data.userids.push(
                        new GPGME_UserId(data.userids[i]));
                }
                break;
            case 'last_update':
                this._data[dataKeys[i]] = new Date( data[dataKeys[i]] * 1000 );
                break;
            default:
                this._data[dataKeys[i]] = data[dataKeys[i]];
            }
        }
        return this;
    }

    /**
     * Query any property of the Key list
     * @param {String} property Key property to be retreived
     * @param {*} cached (optional) if false, the data will be directly queried
     * from gnupg.
     *  @returns {*|Promise<*>} the value, or if not cached, a Promise
     * resolving on the value
     */
    get(property, cached=true) {
        if (cached === false) {
            let me = this;
            return new Promise(function(resolve, reject) {
                if (!validKeyProperties.hasOwnProperty(property)){
                    reject('PARAM_WRONG');
                } else if (property === 'armored'){
                    resolve(me.getArmor());
                } else if (property === 'hasSecret'){
                    resolve(me.getHasSecret());
                } else {
                    me.refreshKey().then(function(key){
                        resolve(key.get(property, true));
                    }, function(error){
                        reject(error);
                    });
                }
            });
        } else {
            if (!validKeyProperties.hasOwnProperty(property)){
                return gpgme_error('PARAM_WRONG');
            }
            if (!this._data.hasOwnProperty(property)){
                return gpgme_error('KEY_NO_INIT');
            } else {
                return (this._data[property]);
            }
        }
    }

    /**
     * Reloads the Key from gnupg
     */
    refreshKey() {
        let me = this;
        return new Promise(function(resolve, reject) {
            if (!me._data.fingerprint){
                reject(gpgme_error('KEY_INVALID'));
            }
            let msg = createMessage('keylist');
            msg.setParameter('sigs', true);
            msg.setParameter('keys', me._data.fingerprint);
            msg.post().then(function(result){
                if (result.keys.length === 1){
                    me.setKeyData(result.keys[0]);
                    resolve(me);
                } else {
                    reject(gpgme_error('KEY_NOKEY'));
                }
            }, function (error) {
                reject(gpgme_error('GNUPG_ERROR'), error);
            });
        });
    }

    /**
     * Query the armored block of the non- secret parts of the Key directly
     * from gpg.
     * @returns {Promise<String>}
     * @async
     */
    getArmor(){
        let me = this;
        return new Promise(function(resolve, reject) {
            if (!me._data.fingerprint){
                reject(gpgme_error('KEY_INVALID'));
            }
            let msg = createMessage('export');
            msg.setParameter('armor', true);
            msg.setParameter('keys', me._data.fingerprint);
            msg.post().then(function(result){
                me._data.armored = result.data;
                resolve(result.data);
            }, function(error){
                reject(error);
            });
        });
    }

    /**
     * Find out if the Key includes a secret part
     * @returns {Promise<Boolean>}
     *
     * @async
     */
    getHasSecret(){
        let me = this;
        return new Promise(function(resolve, reject) {
            if (!me._data.fingerprint){
                reject(gpgme_error('KEY_INVALID'));
            }
            let msg = createMessage('keylist');
            msg.setParameter('keys', me._data.fingerprint);
            msg.setParameter('secret', true);
            msg.post().then(function(result){
                me._data.hasSecret = null;
                if (
                    result.keys &&
                    result.keys.length === 1 &&
                    result.keys[0].secret === true
                ) {
                    me._data.hasSecret = true;
                    resolve(true);
                } else {
                    me._data.hasSecret = false;
                    resolve(false);
                }
            }, function(error){
                reject(error);
            });
        });
    }

    /**
     * Convenience functions to be directly used as properties of the Key
     * Notice that these rely on cached info and may be outdated. Use the async
     * get(property, false) if you need the most current info
     */

    /**
     * @returns {String} The armored public Key block
     */
    get armored(){
        return this.get('armored', true);
    }

    /**
     * @returns {Boolean} If the key is considered a "private Key",
     * i.e. owns a secret subkey.
     */
    get hasSecret(){
        return this.get('hasSecret', true);
    }

    /**
     * Deletes the public Key from the GPG Keyring. Note that a deletion of a
     * secret key is not supported by the native backend.
     * @returns {Promise<Boolean>} Success if key was deleted, rejects with a
     * GPG error otherwise
     */
    delete(){
        let me = this;
        return new Promise(function(resolve, reject){
            if (!me._data.fingerprint){
                reject(gpgme_error('KEY_INVALID'));
            }
            let msg = createMessage('delete');
            msg.setParameter('key', me._data.fingerprint);
            msg.post().then(function(result){
                resolve(result.success);
            }, function(error){
                reject(error);
            });
        });
    }
}

/**
 * The subkeys of a Key. Currently, they cannot be refreshed separately
 */
class GPGME_Subkey {

    constructor(data){
        let keys = Object.keys(data);
        for (let i=0; i< keys.length; i++) {
            this.setProperty(keys[i], data[keys[i]]);
        }
    }

    setProperty(property, value){
        if (!this._data){
            this._data = {};
        }
        if (validSubKeyProperties.hasOwnProperty(property)){
            if (validSubKeyProperties[property](value) === true) {
                if (property === 'timestamp' || property === 'expires'){
                    this._data[property] = new Date(value * 1000);
                } else {
                    this._data[property] = value;
                }
            }
        }
    }

    /**
     *
     * @param {String} property Information to request
     * @returns {String | Number}
     * TODO: date properties are numbers with Date in seconds
     */
    get(property) {
        if (this._data.hasOwnProperty(property)){
            return (this._data[property]);
        }
    }
}

class GPGME_UserId {

    constructor(data){
        let keys = Object.keys(data);
        for (let i=0; i< keys.length; i++) {
            this.setProperty(keys[i], data[keys[i]]);
        }
    }

    setProperty(property, value){
        if (!this._data){
            this._data = {};
        }
        if (validUserIdProperties.hasOwnProperty(property)){
            if (validUserIdProperties[property](value) === true) {
                if (property === 'last_update'){
                    this._data[property] = new Date(value*1000);
                } else {
                    this._data[property] = value;
                }
            }
        }

    }

    /**
     *
     * @param {String} property Information to request
     * @returns {String | Number}
     * TODO: date properties are numbers with Date in seconds
     */
    get(property) {
        if (this._data.hasOwnProperty(property)){
            return (this._data[property]);
        }
    }
}

const validUserIdProperties = {
    'revoked': function(value){
        return typeof(value) === 'boolean';
    },
    'invalid':  function(value){
        return typeof(value) === 'boolean';
    },
    'uid': function(value){
        if (typeof(value) === 'string' || value === ''){
            return true;
        }
        return false;
    },
    'validity': function(value){
        if (typeof(value) === 'string'){
            return true;
        }
        return false;
    },
    'name': function(value){
        if (typeof(value) === 'string' || value === ''){
            return true;
        }
        return false;
    },
    'email': function(value){
        if (typeof(value) === 'string' || value === ''){
            return true;
        }
        return false;
    },
    'address': function(value){
        if (typeof(value) === 'string' || value === ''){
            return true;
        }
        return false;
    },
    'comment': function(value){
        if (typeof(value) === 'string' || value === ''){
            return true;
        }
        return false;
    },
    'origin':  function(value){
        return Number.isInteger(value);
    },
    'last_update':  function(value){
        return Number.isInteger(value);
    }
};

const validSubKeyProperties = {
    'invalid': function(value){
        return typeof(value) === 'boolean';
    },
    'can_encrypt': function(value){
        return typeof(value) === 'boolean';
    },
    'can_sign': function(value){
        return typeof(value) === 'boolean';
    },
    'can_certify':  function(value){
        return typeof(value) === 'boolean';
    },
    'can_authenticate':  function(value){
        return typeof(value) === 'boolean';
    },
    'secret': function(value){
        return typeof(value) === 'boolean';
    },
    'is_qualified': function(value){
        return typeof(value) === 'boolean';
    },
    'is_cardkey':  function(value){
        return typeof(value) === 'boolean';
    },
    'is_de_vs':  function(value){
        return typeof(value) === 'boolean';
    },
    'pubkey_algo_name': function(value){
        return typeof(value) === 'string';
        // TODO: check against list of known?['']
    },
    'pubkey_algo_string': function(value){
        return typeof(value) === 'string';
        // TODO: check against list of known?['']
    },
    'keyid': function(value){
        return isLongId(value);
    },
    'pubkey_algo': function(value) {
        return (Number.isInteger(value) && value >= 0);
    },
    'length': function(value){
        return (Number.isInteger(value) && value > 0);
    },
    'timestamp': function(value){
        return (Number.isInteger(value) && value > 0);
    },
    'expires': function(value){
        return (Number.isInteger(value) && value > 0);
    }
};
const validKeyProperties = {
    //TODO better validation?
    'fingerprint': function(value){
        return isFingerprint(value);
    },
    'armored': function(value){
        return typeof(value === 'string');
    },
    'revoked': function(value){
        return typeof(value) === 'boolean';
    },
    'expired': function(value){
        return typeof(value) === 'boolean';
    },
    'disabled': function(value){
        return typeof(value) === 'boolean';
    },
    'invalid': function(value){
        return typeof(value) === 'boolean';
    },
    'can_encrypt': function(value){
        return typeof(value) === 'boolean';
    },
    'can_sign': function(value){
        return typeof(value) === 'boolean';
    },
    'can_certify': function(value){
        return typeof(value) === 'boolean';
    },
    'can_authenticate': function(value){
        return typeof(value) === 'boolean';
    },
    'secret': function(value){
        return typeof(value) === 'boolean';
    },
    'is_qualified': function(value){
        return typeof(value) === 'boolean';
    },
    'protocol': function(value){
        return typeof(value) === 'string';
        //TODO check for implemented ones
    },
    'issuer_serial': function(value){
        return typeof(value) === 'string';
    },
    'issuer_name': function(value){
        return typeof(value) === 'string';
    },
    'chain_id': function(value){
        return typeof(value) === 'string';
    },
    'owner_trust': function(value){
        return typeof(value) === 'string';
    },
    'last_update': function(value){
        return (Number.isInteger(value));
        //TODO undefined/null possible?
    },
    'origin': function(value){
        return (Number.isInteger(value));
    },
    'subkeys': function(value){
        return (Array.isArray(value));
    },
    'userids': function(value){
        return (Array.isArray(value));
    },
    'tofu': function(value){
        return (Array.isArray(value));
    },
    'hasSecret': function(value){
        return typeof(value) === 'boolean';
    }

};
