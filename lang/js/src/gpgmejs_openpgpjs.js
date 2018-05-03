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

/**
 * This is a compatibility API to be used as openpgpjs syntax.
 * Non-implemented options will throw an error if set (not null or undefined)
 * TODO Some info about differences
 */

 import { GpgME } from "./gpgmejs";
 import {GPGME_Keyring}  from "./Keyring"
 import { GPGME_Key, createKey } from "./Key";
 import { isFingerprint } from "./Helpers"
 import { gpgme_error } from "./Errors"
import { Connection } from "./Connection";


 export class GpgME_openpgpmode {

    constructor(connection, config = {}){
        this.initGpgME(connection, config);
    }

    get Keyring(){
        if (this._keyring){
            return this._keyring;
        }
        return undefined;
    }

    initGpgME(connection, config = {}){
        if (connection && typeof(config) ==='object'){
            this._config = config;
            if (!this._GpgME){
                this._GpgME = new GpgME(connection, config);
            }
            if (!this._keyring){
                this._keyring = new GPGME_Keyring_openpgpmode(connection);
            }
        }
    }

    /**
     * Encrypt Message
     * Supported:
     * @param  {String|Uint8Array} data
     * //an openpgp Message also accepted here. TODO: is this wanted?
     * @param  {Key|Array<Key>} publicKeys
     * //Strings of Fingerprints
     * @param  {Boolean} wildcard
     * TODO:
     * @param  {Key|Array<Key>} privateKeys // -> encryptsign
     * @param  {module:enums.compression} compression //TODO accepts integer, if 0 (no compression) it won't compress
     * @param  {Boolean} armor // TODO base64 switch
     * @param  {Boolean} detached // --> encryptsign
     * unsupported:
     * @param  {String|Array<String>} passwords
     * @param  {Object} sessionKey
     * @param  {Signature} signature
     * @param  {Boolean} returnSessionKey
     * @param  {String} filename
     *
     * Can be set, but will be ignored:
     *
     * @returns {Promise<Object>}
     *      {data: ASCII armored message,
     *      signature: detached signature if 'detached' is true
     *      }
    * @async
    * @static
    */
    encrypt({data = '', publicKeys = '', privateKeys, passwords=null,
        sessionKey = null, filename, compression, armor=true, detached=false,
        signature=null, returnSessionKey=null, wildcard=false, date=null}) {
        if (passwords !== null
            || sessionKey !== null
            || signature !== null
            || returnSessionKey !== null
            || date !== null
            ){
            return Promise.reject(GPMGEJS_Error('NOT_IMPLEMENTED'));
        }
        if ( privateKeys
            || compression
            || armor === false
            || detached == true){
                return Promise.reject(gpgme_error('NOT_YET_IMPLEMENTED'));
        }
        if (filename){
            if (this._config.unconsidered_params === 'warn'){
                GPMGEJS_Error('PARAM_IGNORED');
            } else if (this._config.unconsidered_params === 'error'){
                return Promise.reject(GPMGEJS_Error('NOT_IMPLEMENTED'));
            }
        }
        return this._GpgME.encrypt(data, translateKeys(publicKeys), wildcard);
    }

    /** Decrypt Message
    * supported openpgpjs parameters:
    * @param {Message|Uint8Array|String} message Message object from openpgpjs
    * Unsupported:
    * @param  {String|Array<String>} passwords
    * @param  {Key|Array<Key>} privateKeys
    * @param  {Object|Array<Object>} sessionKeys
    * Not yet supported, but planned
    * @param  {String} format                    (optional) return data format either as 'utf8' or 'binary'
    * @param  {Signature} signature              (optional) detached signature for verification
    * Ignored values: can be safely set, but have no effect
    * @param  {Date} date
    * @param  {Key|Array<Key>} publicKeys
    *
    * @returns {Promise<Object>}             decrypted and verified message in the form:
    *                                         { data:Uint8Array|String, filename:String, signatures:[{ keyid:String, valid:Boolean }] }
    * @async
    * @static
    */
    decrypt({ message, privateKeys, passwords=null, sessionKeys,
        publicKeys, format='utf8', signature=null, date= null}) {
        if (passwords !== null || sessionKeys || privateKeys){
            return Promise.reject(gpgme_error('NOT_IMPLEMENTED'));
        }
        if ( format !== 'utf8' || signature){
            return Promise.reject(gpgme_error('NOT_YET_IMPLEMENTED'));
        }
        if (date !== null || publicKeys){
            if (this._config.unconsidered_params === 'warn'){
                GPMGEJS_Error('PARAM_IGNORED');
            } else if (this._config.unconsidered_params === 'reject'){
                return Promise.reject(GPMGEJS_Error('NOT_IMPLEMENTED'));
            }
        }
        return this._GpgME.decrypt(message);
        // TODO: translate between:
        // openpgp:
        // { data:Uint8Array|String,
        //      filename:String,
        //      signatures:[{ keyid:String, valid:Boolean }] }
        // and gnupg:
        // data:   The decrypted data.  This may be base64 encoded.
        // base64: Boolean indicating whether data is base64 encoded.
        // mime:   A Boolean indicating whether the data is a MIME object.
        // info:   An optional object with extra information.
    }
}

/**
 * Translation layer offering basic Keyring API to be used in Mailvelope.
 * It may still be changed/expanded/merged with GPGME_Keyring
 */
class GPGME_Keyring_openpgpmode {
    constructor(connection){
        this._gpgme_keyring = new GPGME_Keyring(connection);
    }

    /**
     * Returns a GPGME_Key Object for each Key in the gnupg Keyring. This
     * includes keys openpgpjs considers 'private' (usable for signing), with
     * the difference that Key.armored will NOT contain any secret information.
     * Please also note that a GPGME_Key does not offer full openpgpjs- Key
     * compatibility.
     * @returns {Array<GPGME_Key_openpgpmode>}
     * //TODO: Check if IsDefault is also always hasSecret
     * TODO Check if async is required
     */
    getPublicKeys(){
        return translateKeys(
            this._gpgme_keyring.getKeys(null, true));
    }

    /**
     * Returns the Default Key used for crypto operation in gnupg.
     * Please note that the armored property does not contained secret key blocks,
     * despite secret blocks being part of the key itself.
     * @returns {Promise <GPGME_Key>}
     */
    getDefaultKey(){
        this._gpgme_keyring.getSubset({defaultKey: true}).then(function(result){
            if (result.length === 1){
                return Promise.resolve(
                    translateKeys(result)[0]);
            }
            else {
                // TODO: Can there be "no default key"?
                // TODO: Can there be several default keys?
                return gpgme_error('TODO');
            }
        }, function(error){
            //TODO
        });
    }

    /**
     * Deletes a Key
     * @param {Object} Object identifying key
     * @param {String} key.fingerprint - fingerprint of the to be deleted key
     * @param {Boolean} key.secret - indicator if private key should be deleted as well

     * @returns {Promise.<Array.<undefined>, Error>} TBD: Not sure what is wanted
     TODO @throws {Error} error.code = ‘KEY_NOT_EXIST’ - there is no key for the given fingerprint
     TODO @throws {Error} error.code = ‘NO_SECRET_KEY’ - secret indicator set, but no secret key exists
     */
    deleteKey(key){
        if (typeof(key) !== "object"){
            return Promise.reject(gpgme_error('PARAM_WRONG'));
        }
        if ( !key.fingerprint || ! isFingerprint(key.fingerprint)){
            return Promise.reject(gpgme_error('PARAM_WRONG'));
        }
        let key_to_delete = createKey(key.fingerprint, this._gpgme_keyring_GpgME);
        return key_to_delete.deleteKey(key.secret);
    }
}

/**
 * TODO error handling.
 * Offers the Key information as the openpgpmode wants
 */
class GPGME_Key_openpgpmode {
    constructor(value, connection){
        this.init(value, connection);
    }

    /**
     * Can be either constructed using an existing GPGME_Key, or a fingerprint
     * and a connection
     * @param {String|GPGME_Key} value
     * @param {Connection} connection
     */
    init (value, connection){
        if (!this._GPGME_Key && value instanceof GPGME_Key){
            this._GPGME_Key = value;
        } else if (!this._GPGME_Key && isFingerprint(value) &&
            connection instanceof Connection){
            this._GPGME_Key = createKey(value, connection);
        }
    }

    get fingerprint(){
        return this._GPGME_Key.fingerprint;
    }

    get armor(){
        return this._GPGME_Key.armored;
    }

    get secret(){
        return this._GPGME_Key.hasSecret;
    }

    get default(){
        return this._GPGME_Key.isDefault;
    }
}

/**
 * creates GPGME_Key_openpgpmode from GPGME_Keys
 * @param {GPGME_Key|Array<GPGME_Key>} input keys
 * @returns {Array<GPGME_Key_openpgpmode>}
 */
function translateKeys(input){
    if (!input){
        return null;
    }
    if (!Array.isArray(input)){
        input = [input];
    }
    let resultset;
    for (let i=0; i< input.length; i++){
        resultset.push(new GPGME_Key_openpgpmode(input[i]));
    }
    return resultset;
}