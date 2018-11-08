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


import { isFingerprint, isLongId } from './Helpers';
import { gpgme_error } from './Errors';
import { createMessage } from './Message';

/**
 * Validates the given fingerprint and creates a new {@link GPGME_Key}
 * @param {String} fingerprint
 * @param {Boolean} async If True, Key properties (except fingerprint) will be
 * queried from gnupg on each call, making the operation up-to-date, the
 * answers will be Promises, and the performance will likely suffer
 * @param {Object} data additional initial properties this Key will have. Needs
 * a full object as delivered by gpgme-json
 * @returns {Object} The verified and updated data
 */
export function createKey (fingerprint, async = false, data){
    if (!isFingerprint(fingerprint) || typeof (async) !== 'boolean'){
        throw gpgme_error('PARAM_WRONG');
    }
    if (data !== undefined){
        data = validateKeyData(fingerprint, data);
    }
    if (data instanceof Error){
        throw gpgme_error('KEY_INVALID');
    } else {
        return new GPGME_Key(fingerprint, async, data);
    }
}

/**
 * Represents the Keys as stored in the gnupg backend. A key is defined by a
 * fingerprint.
 * A key cannot be directly created via the new operator, please use
 * {@link createKey} instead.
 * A GPGME_Key object allows to query almost all information defined in gpgme
 * Keys. It offers two modes, async: true/false. In async mode, Key properties
 * with the exception of the fingerprint will be queried from gnupg on each
 * call, making the operation up-to-date, the answers will be Promises, and
 * the performance will likely suffer. In Sync modes, all information except
 * for the armored Key export will be cached and can be refreshed by
 * [refreshKey]{@link GPGME_Key#refreshKey}.
 *
 * <pre>
 * see also:
 *      {@link GPGME_UserId} user Id objects
 *      {@link GPGME_Subkey} subKey objects
 * </pre>
 * For other Key properteis, refer to {@link validKeyProperties},
 * and to the [gpgme documentation]{@link https://www.gnupg.org/documentation/manuals/gpgme/Key-objects.html}
 * for meanings and further details.
 *
 * @class
 */
class GPGME_Key {

    constructor (fingerprint, async, data){

        /**
         * @property {Boolean} _async If true, the Key was initialized without
         * cached data
         */
        this._async = async;

        this._data = { fingerprint: fingerprint.toUpperCase() };
        if (data !== undefined
            && data.fingerprint.toUpperCase() === this._data.fingerprint
        ) {
            this._data = data;
        }
    }

    /**
     * Query any property of the Key listed in {@link validKeyProperties}
     * @param {String} property property to be retrieved
     * @returns {Boolean| String | Date | Array | Object}
     * @returns {Promise<Boolean| String | Date | Array | Object>} (if in async
     * mode)
     * <pre>
     * Returns the value of the property requested. If the Key is set to async,
     * the value will be fetched from gnupg and resolved as a Promise. If Key
     * is not  async, the armored property is not available (it can still be
     * retrieved asynchronously by [getArmor]{@link GPGME_Key#getArmor})
     */
    get (property) {
        if (this._async === true) {
            switch (property){
            case 'armored':
                return this.getArmor();
            case 'hasSecret':
                return this.getGnupgSecretState();
            default:
                return getGnupgState(this.fingerprint, property);
            }
        } else {
            if (property === 'armored') {
                throw gpgme_error('KEY_ASYNC_ONLY');
            }
            // eslint-disable-next-line no-use-before-define
            if (!validKeyProperties.hasOwnProperty(property)){
                throw gpgme_error('PARAM_WRONG');
            } else {
                return (this._data[property]);
            }
        }
    }

    /**
     * Reloads the Key information from gnupg. This is only useful if the Key
     * use the GPGME_Keys cached. Note that this is a performance hungry
     * operation. If you desire more than a few refreshs, it may be
     * advisable to run [Keyring.getKeys]{@link Keyring#getKeys} instead.
     * @returns {Promise<GPGME_Key>}
     * @async
     */
    refreshKey () {
        let me = this;
        return new Promise(function (resolve, reject) {
            if (!me._data.fingerprint){
                reject(gpgme_error('KEY_INVALID'));
            }
            let msg = createMessage('keylist');
            msg.setParameter('sigs', true);
            msg.setParameter('keys', me._data.fingerprint);
            msg.post().then(function (result){
                if (result.keys.length === 1){
                    const newdata = validateKeyData(
                        me._data.fingerprint, result.keys[0]);
                    if (newdata instanceof Error){
                        reject(gpgme_error('KEY_INVALID'));
                    } else {
                        me._data = newdata;
                        me.getGnupgSecretState().then(function (){
                            me.getArmor().then(function (){
                                resolve(me);
                            }, function (error){
                                reject(error);
                            });
                        }, function (error){
                            reject(error);
                        });
                    }
                } else {
                    reject(gpgme_error('KEY_NOKEY'));
                }
            }, function (error) {
                reject(gpgme_error('GNUPG_ERROR'), error);
            });
        });
    }

    /**
     * Query the armored block of the Key directly from gnupg. Please note
     * that this will not get you any export of the secret/private parts of
     * a Key
     * @returns {Promise<String>}
     * @async
     */
    getArmor () {
        const me = this;
        return new Promise(function (resolve, reject) {
            if (!me._data.fingerprint){
                reject(gpgme_error('KEY_INVALID'));
            }
            let msg = createMessage('export');
            msg.setParameter('armor', true);
            msg.setParameter('keys', me._data.fingerprint);
            msg.post().then(function (result){
                resolve(result.data);
            }, function (error){
                reject(error);
            });
        });
    }

    /**
     * Find out if the Key is part of a Key pair including public and
     * private key(s). If you want this information about more than a few
     * Keys in synchronous mode, it may be advisable to run
     * [Keyring.getKeys]{@link Keyring#getKeys} instead, as it performs faster
     * in bulk querying.
     * @returns {Promise<Boolean>} True if a private Key is available in the
     * gnupg Keyring.
     * @async
     */
    getGnupgSecretState (){
        const me = this;
        return new Promise(function (resolve, reject) {
            if (!me._data.fingerprint){
                reject(gpgme_error('KEY_INVALID'));
            } else {
                let msg = createMessage('keylist');
                msg.setParameter('keys', me._data.fingerprint);
                msg.setParameter('secret', true);
                msg.post().then(function (result){
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
                }, function (error){
                    reject(error);
                });
            }
        });
    }

    /**
     * Deletes the (public) Key from the GPG Keyring. Note that a deletion
     * of a secret key is not supported by the native backend, and gnupg will
     * refuse to delete a Key if there is still a secret/private Key present
     * to that public Key
     * @returns {Promise<Boolean>} Success if key was deleted.
     */
    delete (){
        const me = this;
        return new Promise(function (resolve, reject){
            if (!me._data.fingerprint){
                reject(gpgme_error('KEY_INVALID'));
            }
            let msg = createMessage('delete');
            msg.setParameter('key', me._data.fingerprint);
            msg.post().then(function (result){
                resolve(result.success);
            }, function (error){
                reject(error);
            });
        });
    }

    /**
     * @returns {String} The fingerprint defining this Key. Convenience getter
     */
    get fingerprint (){
        return this._data.fingerprint;
    }
}

/**
 * Representing a subkey of a Key. See {@link validSubKeyProperties} for
 * possible properties.
 * @class
 * @protected
 */
class GPGME_Subkey {

    /**
     * Initializes with the json data sent by gpgme-json
     * @param {Object} data
     * @private
     */
    constructor (data){
        this._data = {};
        let keys = Object.keys(data);
        const me = this;

        /**
         * Validates a subkey property against {@link validSubKeyProperties} and
         * sets it if validation is successful
         * @param {String} property
         * @param {*} value
         * @param private
         */
        const setProperty = function (property, value){
            // eslint-disable-next-line no-use-before-define
            if (validSubKeyProperties.hasOwnProperty(property)){
                // eslint-disable-next-line no-use-before-define
                if (validSubKeyProperties[property](value) === true) {
                    if (property === 'timestamp' || property === 'expires'){
                        me._data[property] = new Date(value * 1000);
                    } else {
                        me._data[property] = value;
                    }
                }
            }
        };
        for (let i=0; i< keys.length; i++) {
            setProperty(keys[i], data[keys[i]]);
        }
    }

    /**
     * Fetches any information about this subkey
     * @param {String} property Information to request
     * @returns {String | Number | Date}
     */
    get (property) {
        if (this._data.hasOwnProperty(property)){
            return (this._data[property]);
        }
    }

}

/**
 * Representing user attributes associated with a Key or subkey. See
 * {@link validUserIdProperties} for possible properties.
 * @class
 * @protected
 */
class GPGME_UserId {

    /**
     * Initializes with the json data sent by gpgme-json
     * @param {Object} data
     * @private
     */
    constructor (data){
        this._data = {};
        const me = this;
        let keys = Object.keys(data);
        const setProperty = function (property, value){
            // eslint-disable-next-line no-use-before-define
            if (validUserIdProperties.hasOwnProperty(property)){
                // eslint-disable-next-line no-use-before-define
                if (validUserIdProperties[property](value) === true) {
                    if (property === 'last_update'){
                        me._data[property] = new Date(value*1000);
                    } else {
                        me._data[property] = value;
                    }
                }
            }
        };
        for (let i=0; i< keys.length; i++) {
            setProperty(keys[i], data[keys[i]]);
        }
    }

    /**
     * Fetches information about the user
     * @param {String} property Information to request
     * @returns {String | Number}
     */
    get (property) {
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
    'revoked': function (value){
        return typeof (value) === 'boolean';
    },
    'invalid':  function (value){
        return typeof (value) === 'boolean';
    },
    'uid': function (value){
        if (typeof (value) === 'string' || value === ''){
            return true;
        }
        return false;
    },
    'validity': function (value){
        if (typeof (value) === 'string'){
            return true;
        }
        return false;
    },
    'name': function (value){
        if (typeof (value) === 'string' || value === ''){
            return true;
        }
        return false;
    },
    'email': function (value){
        if (typeof (value) === 'string' || value === ''){
            return true;
        }
        return false;
    },
    'address': function (value){
        if (typeof (value) === 'string' || value === ''){
            return true;
        }
        return false;
    },
    'comment': function (value){
        if (typeof (value) === 'string' || value === ''){
            return true;
        }
        return false;
    },
    'origin':  function (value){
        return Number.isInteger(value);
    },
    'last_update':  function (value){
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
    'invalid': function (value){
        return typeof (value) === 'boolean';
    },
    'can_encrypt': function (value){
        return typeof (value) === 'boolean';
    },
    'can_sign': function (value){
        return typeof (value) === 'boolean';
    },
    'can_certify':  function (value){
        return typeof (value) === 'boolean';
    },
    'can_authenticate':  function (value){
        return typeof (value) === 'boolean';
    },
    'secret': function (value){
        return typeof (value) === 'boolean';
    },
    'is_qualified': function (value){
        return typeof (value) === 'boolean';
    },
    'is_cardkey':  function (value){
        return typeof (value) === 'boolean';
    },
    'is_de_vs':  function (value){
        return typeof (value) === 'boolean';
    },
    'pubkey_algo_name': function (value){
        return typeof (value) === 'string';
        // TODO: check against list of known?['']
    },
    'pubkey_algo_string': function (value){
        return typeof (value) === 'string';
        // TODO: check against list of known?['']
    },
    'keyid': function (value){
        return isLongId(value);
    },
    'pubkey_algo': function (value) {
        return (Number.isInteger(value) && value >= 0);
    },
    'length': function (value){
        return (Number.isInteger(value) && value > 0);
    },
    'timestamp': function (value){
        return (Number.isInteger(value) && value > 0);
    },
    'expires': function (value){
        return (Number.isInteger(value) && value > 0);
    }
};

/**
 * Validation definition for Keys. Each valid Key property is represented
 * as a key-value pair, with their value being a validation function. For
 * details on the meanings, please refer to the gpgme documentation
 * https://www.gnupg.org/documentation/manuals/gpgme/Key-objects.html#Key-objects
 * @param {String} fingerprint
 * @param {Boolean} revoked
 * @param {Boolean} expired
 * @param {Boolean} disabled
 * @param {Boolean} invalid
 * @param {Boolean} can_encrypt
 * @param {Boolean} can_sign
 * @param {Boolean} can_certify
 * @param {Boolean} can_authenticate
 * @param {Boolean} secret
 * @param {Boolean}is_qualified
 * @param {String} protocol
 * @param {String} issuer_serial
 * @param {String} issuer_name
 * @param {Boolean} chain_id
 * @param {String} owner_trust
 * @param {Date} last_update
 * @param {String} origin
 * @param {Array<GPGME_Subkey>} subkeys
 * @param {Array<GPGME_UserId>} userids
 * @param {Array<String>} tofu
 * @param {Boolean} hasSecret
 * @protected
 * @const
 */
const validKeyProperties = {
    'fingerprint': function (value){
        return isFingerprint(value);
    },
    'revoked': function (value){
        return typeof (value) === 'boolean';
    },
    'expired': function (value){
        return typeof (value) === 'boolean';
    },
    'disabled': function (value){
        return typeof (value) === 'boolean';
    },
    'invalid': function (value){
        return typeof (value) === 'boolean';
    },
    'can_encrypt': function (value){
        return typeof (value) === 'boolean';
    },
    'can_sign': function (value){
        return typeof (value) === 'boolean';
    },
    'can_certify': function (value){
        return typeof (value) === 'boolean';
    },
    'can_authenticate': function (value){
        return typeof (value) === 'boolean';
    },
    'secret': function (value){
        return typeof (value) === 'boolean';
    },
    'is_qualified': function (value){
        return typeof (value) === 'boolean';
    },
    'protocol': function (value){
        return typeof (value) === 'string';
        // TODO check for implemented ones
    },
    'issuer_serial': function (value){
        return typeof (value) === 'string';
    },
    'issuer_name': function (value){
        return typeof (value) === 'string';
    },
    'chain_id': function (value){
        return typeof (value) === 'string';
    },
    'owner_trust': function (value){
        return typeof (value) === 'string';
    },
    'last_update': function (value){
        return (Number.isInteger(value));
        // TODO undefined/null possible?
    },
    'origin': function (value){
        return (Number.isInteger(value));
    },
    'subkeys': function (value){
        return (Array.isArray(value));
    },
    'userids': function (value){
        return (Array.isArray(value));
    },
    'tofu': function (value){
        return (Array.isArray(value));
    },
    'hasSecret': function (value){
        return typeof (value) === 'boolean';
    }

};

/**
* sets the Key data in bulk. It can only be used from inside a Key, either
* during construction or on a refresh callback.
* @param {Object} key the original internal key data.
* @param {Object} data Bulk set the data for this key, with an Object structure
* as sent by gpgme-json.
* @returns {Object|GPGME_Error} the changed data after values have been set,
* an error if something went wrong.
* @private
*/
function validateKeyData (fingerprint, data){
    const key = {};
    if (!fingerprint || typeof (data) !== 'object' || !data.fingerprint
     || fingerprint !== data.fingerprint.toUpperCase()
    ){
        return gpgme_error('KEY_INVALID');
    }
    let props = Object.keys(data);
    for (let i=0; i< props.length; i++){
        if (!validKeyProperties.hasOwnProperty(props[i])){
            return gpgme_error('KEY_INVALID');
        }
        // running the defined validation function
        if (validKeyProperties[props[i]](data[props[i]]) !== true ){
            return gpgme_error('KEY_INVALID');
        }
        switch (props[i]){
        case 'subkeys':
            key.subkeys = [];
            for (let i=0; i< data.subkeys.length; i++) {
                key.subkeys.push(
                    new GPGME_Subkey(data.subkeys[i]));
            }
            break;
        case 'userids':
            key.userids = [];
            for (let i=0; i< data.userids.length; i++) {
                key.userids.push(
                    new GPGME_UserId(data.userids[i]));
            }
            break;
        case 'last_update':
            key[props[i]] = new Date( data[props[i]] * 1000 );
            break;
        default:
            key[props[i]] = data[props[i]];
        }
    }
    return key;
}

/**
 * Fetches and sets properties from gnupg
 * @param {String} fingerprint
 * @param {String} property to search for.
 * @private
 * @async
 */
function getGnupgState (fingerprint, property){
    return new Promise(function (resolve, reject) {
        if (!isFingerprint(fingerprint)) {
            reject(gpgme_error('KEY_INVALID'));
        } else {
            let msg = createMessage('keylist');
            msg.setParameter('keys', fingerprint);
            msg.post().then(function (res){
                if (!res.keys || res.keys.length !== 1){
                    reject(gpgme_error('KEY_INVALID'));
                } else {
                    const key = res.keys[0];
                    let result;
                    switch (property){
                    case 'subkeys':
                        result = [];
                        if (key.subkeys.length){
                            for (let i=0; i < key.subkeys.length; i++) {
                                result.push(
                                    new GPGME_Subkey(key.subkeys[i]));
                            }
                        }
                        resolve(result);
                        break;
                    case 'userids':
                        result = [];
                        if (key.userids.length){
                            for (let i=0; i< key.userids.length; i++) {
                                result.push(
                                    new GPGME_UserId(key.userids[i]));
                            }
                        }
                        resolve(result);
                        break;
                    case 'last_update':
                        if (key.last_update === undefined){
                            reject(gpgme_error('CONN_UNEXPECTED_ANSWER'));
                        } else if (key.last_update !== null){
                            resolve(new Date( key.last_update * 1000));
                        } else {
                            resolve(null);
                        }
                        break;
                    default:
                        if (!validKeyProperties.hasOwnProperty(property)){
                            reject(gpgme_error('PARAM_WRONG'));
                        } else {
                            if (key.hasOwnProperty(property)){
                                resolve(key[property]);
                            } else {
                                reject(gpgme_error(
                                    'CONN_UNEXPECTED_ANSWER'));
                            }
                        }
                        break;
                    }
                }
            }, function (error){
                reject(gpgme_error(error));
            });
        }
    });
}
