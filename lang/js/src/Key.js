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
 * @param {Boolean} async If True, Key properties (except fingerprint) will be
 * queried from gnupg on each call, making the operation up-to-date, the
 * answers will be Promises, and the performance will likely suffer
 * @returns {GPGME_Key|GPGME_Error}
 */
export function createKey(fingerprint, async = false){
    if (!isFingerprint(fingerprint) || typeof(async) !== 'boolean'){
        return gpgme_error('PARAM_WRONG');
    }
    else return Object.freeze(new GPGME_Key(fingerprint, async));
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

    constructor(fingerprint, async){

        /**
         * @property {Boolean} If true, most answers will be asynchronous
         */
        this.isAsync = async;

        let _data = {fingerprint: fingerprint};
        this.getFingerprint = function(){
            if (!_data.fingerprint || !isFingerprint(_data.fingerprint)){
                return gpgme_error('KEY_INVALID');
            }
            return _data.fingerprint;
        };

        /**
         * Property indicating if the Key possesses a private/secret part. If
         * this information is not yet cached, it returns an
         * {@link GPGME_Error} with code 'KEY_NO_INIT'. Running
         * {@link refreshKey} may help in this case.
         * @returns {Boolean} If the Key has a secret subkey.
         */
        this.hasSecret= function (){
            return this.get('hasSecret');
        };

        /**
         * @param {Object} data Bulk set the data for this key, with an Object
         * sent by gpgme-json.
         * @returns {GPGME_Key|GPGME_Error} Itself after values have been set,
         * an error if something went wrong.
         * @private
         */
        this.setKeyData = function (data){
            if (typeof(data) !== 'object') {
                return gpgme_error('KEY_INVALID');
            }
            if (!data.fingerprint || data.fingerprint !== _data.fingerprint){
                return gpgme_error('KEY_INVALID');
            }
            let keys = Object.keys(data);
            for (let i=0; i< keys.length; i++){
                if (!validKeyProperties.hasOwnProperty(keys[i])){
                    return gpgme_error('KEY_INVALID');
                }
                //running the defined validation function
                if (validKeyProperties[keys[i]](data[keys[i]]) !== true ){
                    return gpgme_error('KEY_INVALID');
                }
                switch (keys[i]){
                case 'subkeys':
                    _data.subkeys = [];
                    for (let i=0; i< data.subkeys.length; i++) {
                        _data.subkeys.push(Object.freeze(
                            new GPGME_Subkey(data.subkeys[i])));
                    }
                    break;
                case 'userids':
                    _data.userids = [];
                    for (let i=0; i< data.userids.length; i++) {
                        _data.userids.push(Object.freeze(
                            new GPGME_UserId(data.userids[i])));
                    }
                    break;
                case 'last_update':
                    _data[keys[i]] = new Date( data[keys[i]] * 1000 );
                    break;
                default:
                    _data[keys[i]] = data[keys[i]];
                }
            }
            return this;
        };

        /**
         * Query any property of the Key listed in {@link validKeyProperties}
         * @param {String} property property to be retreived
         * @returns {*|Promise<*>} the value (Boolean, String, Array, Object).
         * If 'cached' is false, the value will be resolved as a Promise.
         */
        this.get = function(property) {
            if (this.isAsync === true) {
                let me = this;
                return new Promise(function(resolve, reject) {
                    if (property === 'armored'){
                        resolve(me.getArmor());
                    } else if (property === 'hasSecret'){
                        resolve(me.getHasSecret());
                    } else if (validKeyProperties.hasOwnProperty(property)){
                        let msg = createMessage('keylist');
                        msg.setParameter('keys', _data.fingerprint);
                        msg.post().then(function(result){
                            if (result.keys && result.keys.length === 1 &&
                                result.keys[0].hasOwnProperty(property)){
                                resolve(result.keys[0][property]);
                            } else {
                                reject(gpgme_error('CONN_UNEXPECTED_ANSWER'));
                            }
                        }, function(error){
                            reject(gpgme_error(error));
                        });
                    } else {
                        reject(gpgme_error('PARAM_WRONG'));
                    }
                });
            } else {
                if (!validKeyProperties.hasOwnProperty(property)){
                    return gpgme_error('PARAM_WRONG');
                }
                if (!_data.hasOwnProperty(property)){
                    return gpgme_error('KEY_NO_INIT');
                } else {
                    return (_data[property]);
                }
            }
        };

        /**
         * Reloads the Key information from gnupg. This is only useful if you
         * use the GPGME_Keys cached. Note that this is a performance hungry
         * operation. If you desire more than a few refreshs, it may be
         * advisable to run {@link Keyring.getKeys} instead.
         * @returns {Promise<GPGME_Key|GPGME_Error>}
         * @async
         */
        this.refreshKey = function() {
            let me = this;
            return new Promise(function(resolve, reject) {
                if (!_data.fingerprint){
                    reject(gpgme_error('KEY_INVALID'));
                }
                let msg = createMessage('keylist');
                msg.setParameter('sigs', true);
                msg.setParameter('keys', _data.fingerprint);
                msg.post().then(function(result){
                    if (result.keys.length === 1){
                        me.setKeyData(result.keys[0]);
                        me.getHasSecret().then(function(){
                            me.getArmor().then(function(){
                                resolve(me);
                            }, function(error){
                                reject(error);
                            });
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
        };

        /**
         * Query the armored block of the Key directly from gnupg. Please note
         * that this will not get you any export of the secret/private parts of
         * a Key
         * @returns {Promise<String|GPGME_Error>}
         * @async
         */
        this.getArmor = function(){
            return new Promise(function(resolve, reject) {
                if (!_data.fingerprint){
                    reject(gpgme_error('KEY_INVALID'));
                }
                let msg = createMessage('export');
                msg.setParameter('armor', true);
                msg.setParameter('keys', _data.fingerprint);
                msg.post().then(function(result){
                    _data.armored = result.data;
                    resolve(result.data);
                }, function(error){
                    reject(error);
                });
            });
        };

        /**
         * Find out if the Key includes a secret part. Note that this is a
         * rather nonperformant operation, as it needs to query gnupg twice.
         * If you want this inforrmation about more than a few Keys, it may be
         * advisable to run {@link Keyring.getKeys} instead.
         * @returns {Promise<Boolean|GPGME_Error>} True if a secret/private Key
         * is available in the gnupg Keyring
         * @async
         */
        this.getHasSecret = function (){
            return new Promise(function(resolve, reject) {
                if (!_data.fingerprint){
                    reject(gpgme_error('KEY_INVALID'));
                }
                let msg = createMessage('keylist');
                msg.setParameter('keys', _data.fingerprint);
                msg.setParameter('secret', true);
                msg.post().then(function(result){
                    _data.hasSecret = null;
                    if (
                        result.keys &&
                        result.keys.length === 1 &&
                        result.keys[0].secret === true
                    ) {
                        _data.hasSecret = true;
                        resolve(true);
                    } else {
                        _data.hasSecret = false;
                        resolve(false);
                    }
                }, function(error){
                    reject(error);
                });
            });
        };

        /**
         * Deletes the (public) Key from the GPG Keyring. Note that a deletion
         * of a secret key is not supported by the native backend.
         * @returns {Promise<Boolean|GPGME_Error>} Success if key was deleted,
         * rejects with a GPG error otherwise.
         */
        this.delete= function (){
            return new Promise(function(resolve, reject){
                if (!_data.fingerprint){
                    reject(gpgme_error('KEY_INVALID'));
                }
                let msg = createMessage('delete');
                msg.setParameter('key', _data.fingerprint);
                msg.post().then(function(result){
                    resolve(result.success);
                }, function(error){
                    reject(error);
                });
            });
        };
    }

    /**
     * @returns {String} The fingerprint defining this Key
     */
    get fingerprint(){
        return this.getFingerprint();
    }

    /**
     * Property for the export of armored Key. If the armored Key is not
     * cached, it returns an {@link GPGME_Error} with code 'KEY_NO_INIT'.
     * Running {@link refreshKey} may help in this case.
     * @returns {String|GPGME_Error} The armored public Key block.
     */
    get armored(){
        return this.get('armored', true);
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
        let _data = {};
        let keys = Object.keys(data);

        /**
         * Validates a subkey property against {@link validSubKeyProperties} and
         * sets it if validation is successful
         * @param {String} property
         * @param {*} value
         * @param private
         */
        const setProperty = function (property, value){
            if (validSubKeyProperties.hasOwnProperty(property)){
                if (validSubKeyProperties[property](value) === true) {
                    if (property === 'timestamp' || property === 'expires'){
                        _data[property] = new Date(value * 1000);
                    } else {
                        _data[property] = value;
                    }
                }
            }
        };
        for (let i=0; i< keys.length; i++) {
            setProperty(keys[i], data[keys[i]]);
        }

        /**
         * Fetches any information about this subkey
         * @param {String} property Information to request
         * @returns {String | Number | Date}
         */
        this.get = function(property) {
            if (_data.hasOwnProperty(property)){
                return (_data[property]);
            }
        };
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
        let _data = {};
        let keys = Object.keys(data);
        const setProperty = function(property, value){
            if (validUserIdProperties.hasOwnProperty(property)){
                if (validUserIdProperties[property](value) === true) {
                    if (property === 'last_update'){
                        _data[property] = new Date(value*1000);
                    } else {
                        _data[property] = value;
                    }
                }
            }
        };
        for (let i=0; i< keys.length; i++) {
            setProperty(keys[i], data[keys[i]]);
        }

        /**
         * Validates a subkey property against {@link validUserIdProperties} and
         * sets it if validation is successful
         * @param {String} property
         * @param {*} value
         * @param private
         */


        /**
         * Fetches information about the user
         * @param {String} property Information to request
         * @returns {String | Number}
         */
        this.get = function (property) {
            if (_data.hasOwnProperty(property)){
                return (_data[property]);
            }
        };
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
