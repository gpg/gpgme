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
 * Validates the given fingerprint and creates a new {@link GPGME_Key}
 * @param {String} fingerprint
 * @returns {GPGME_Key|GPGME_Error}
 */
export function createKey(fingerprint){
    if (!isFingerprint(fingerprint)){
        return gpgme_error('PARAM_WRONG');
    }
    else return new GPGME_Key(fingerprint);
}

/**
 * Represents the Keys as stored in the gnupg backend
 * It allows to query almost all information defined in gpgme Key Objects
 * Refer to {@link validKeyProperties} for available information, and the gpgme
 * documentation on their meaning
 * (https://www.gnupg.org/documentation/manuals/gpgme/Key-objects.html)
 *
 * @class
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

    /**
     * @returns {String} The fingerprint defining this Key
     */
    get fingerprint(){
        if (!this._data || !this._data.fingerprint){
            return gpgme_error('KEY_INVALID');
        }
        return this._data.fingerprint;
    }

    /**
     * @param {Object} data Bulk set the data for this key, with an Object sent
     * by gpgme-json.
     * @returns {GPGME_Key|GPGME_Error} Itself after values have been set, an
     * error if something went wrong
     * @private
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
     * Query any property of the Key listed in {@link validKeyProperties}
     * @param {String} property property to be retreived
     * @param {Boolean} cached (optional) if false, the data will be directly
     * queried from gnupg, and the operation will be asynchronous. Else, the
     * data will be fetched from the state of the initialization of the Key.
     * The cached mode may contain outdated information, but can be used as
     * synchronous operation, where the backend is not expected to change Keys
     * during a session. The key still can be reloaded by invoking
     * {@link refreshKey}.
     * @returns {*|Promise<*>} the value (Boolean, String, Array, Object).
     * If 'cached' is true, the value will be resolved as a Promise.
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
     * Reloads the Key information from gnupg. This is only useful if you use
     * the GPGME_Keys cached. Note that this is a performance hungry operation.
     * If you desire more than a few refreshs, it may be advisable to run
     * {@link Keyring.getKeys} instead.
     * @returns {Promise<GPGME_Key|GPGME_Error>}
     * @async
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
                    me.getHasSecret().then(function(){
                        //TODO retrieve armored Key
                        resolve(me);
                    }, function(error){
                        reject(error);
                    });
                } else {
                    reject(gpgme_error('KEY_NOKEY'));
                }
            }, function (error) {
                reject(gpgme_error('GNUPG_ERROR'), error);
            });
        });
    }

    /**
     * Query the armored block of the Key directly from gnupg. Please note that
     * this will not get you any export of the secret/private parts of a Key
     * @returns {Promise<String|GPGME_Error>}
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
     * Find out if the Key includes a secret part. Note that this is a rather
     * nonperformant operation, as it needs to query gnupg twice. If you want
     * this inforrmation about more than a few Keys, it may be advisable to run
     * {@link Keyring.getKeys} instead.
     * @returns {Promise<Boolean|GPGME_Error>} True if a secret/private Key is
     * available in the gnupg Keyring
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
     * Property for the export of armored Key. If the armored Key is not
     * cached, it returns an {@link GPGME_Error} with code 'KEY_NO_INIT'.
     * Running {@link refreshKey} may help in this case.
     * @returns {String|GPGME_Error} The armored public Key block.
     */
    get armored(){
        return this.get('armored', true);
    }

    /**
     * Property indicating if the Key possesses a private/secret part. If this
     * information is not yet cached, it returns an {@link GPGME_Error} with
     * code 'KEY_NO_INIT'.  Running {@link refreshKey} may help in this case.
     * @returns {Boolean} If the Key has a secret subkey.
     */
    get hasSecret(){
        return this.get('hasSecret', true);
    }

    /**
     * Deletes the (public) Key from the GPG Keyring. Note that a deletion of a
     * secret key is not supported by the native backend.
     * @returns {Promise<Boolean|GPGME_Error>} Success if key was deleted,
     * rejects with a GPG error otherwise.
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
 * Representing a subkey of a Key.
 * @class
 * @protected
 */
class GPGME_Subkey {

    /**
     * Initializes with the json data sent by gpgme-json
     * @param {Object} data
     * @private
     */
    constructor(data){
        let keys = Object.keys(data);
        for (let i=0; i< keys.length; i++) {
            this.setProperty(keys[i], data[keys[i]]);
        }
    }

    /**
     * Validates a subkey property against {@link validSubKeyProperties} and
     * sets it if validation is successful
     * @param {String} property
     * @param {*} value
     * @param private
     */
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
     * Fetches any information about this subkey
     * @param {String} property Information to request
     * @returns {String | Number | Date}
     */
    get(property) {
        if (this._data.hasOwnProperty(property)){
            return (this._data[property]);
        }
    }
}

/**
 * Representing user attributes associated with a Key or subkey
 * @class
 * @protected
 */
class GPGME_UserId {

    /**
     * Initializes with the json data sent by gpgme-json
     * @param {Object} data
     * @private
     */
    constructor(data){
        let keys = Object.keys(data);
        for (let i=0; i< keys.length; i++) {
            this.setProperty(keys[i], data[keys[i]]);
        }
    }
    /**
     * Validates a subkey property against {@link validUserIdProperties} and
     * sets it if validation is successful
     * @param {String} property
     * @param {*} value
     * @param private
     */
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
     * Fetches information about the user
     * @param {String} property Information to request
     * @returns {String | Number}
     */
    get(property) {
        if (this._data.hasOwnProperty(property)){
            return (this._data[property]);
        }
    }
}

/**
 * Validation definition for userIds. Each valid userId property is represented
 * as a key- Value pair, with their value being a validation function to check
 * against
 * @protected
 * @const
 */
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

/**
 * Validation definition for subKeys. Each valid userId property is represented
 * as a key-value pair, with the value being a validation function
 * @protected
 * @const
 */
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

/**
 * Validation definition for Keys. Each valid Key property is represented
 * as a key-value pair, with their value being a validation function
 * @protected
 * @const
 */
const validKeyProperties = {
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
