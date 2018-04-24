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
 import { GPGME_Key } from "./Key";
 import { isFingerprint } from "./Helpers"
 import { GPGMEJS_Error } from './Errors'


 export class GpgME_openpgpmode {

    constructor(connection){
        this.initGpgME(connection);
    }

    get Keyring(){
        if (this._keyring){
            return this._keyring;
        }
        return undefined;
    }

    initGpgME(connection){
        this._GpgME = new GpgME(connection);
        this._Keyring = new GPGME_Keyring_openpgpmode(connection);
    }

    get GpgME(){
        if (this._GpGME){
            return this._GpGME;
        }
    }

    /**
     * Encrypt Message
     * Supported:
     * @param  {String|Uint8Array} data
     * @param  {Key|Array<Key>} publicKeys
     * @param  {Boolean} wildcard
     * TODO:
     * @param  {Key|Array<Key>} privateKeys
     * @param  {String} filename
     * @param  {module:enums.compression} compression
     * @param  {Boolean} armor
     * @param  {Boolean} detached
     * unsupported:
     * @param  {String|Array<String>} passwords
     * @param  {Object} sessionKey
     * @param  {Signature} signature
     * @param  {Boolean} returnSessionKey
     *
     * @returns {Promise<Object>}
     *      {data: ASCII armored message,
     *      signature: detached signature if 'detached' is true
     *      }
    * @async
    * @static
    */
    encrypt({data = '', publicKeys = '', privateKeys, passwords, sessionKey,
        filename, compression, armor=true, detached=false, signature=null,
        returnSessionKey=null, wildcard=false, date=null}) {
        if (passwords !== undefined
            || sessionKey !== undefined
            || signature !== null
            || returnSessionKey !== null
            || date !== null){
            return Promise.reject(new GPMGEJS_Error('NOT_IMPLEMENTED'));
        }
        if ( privateKeys
            || filename
            || compression
            || armor === false
            || detached == true){
                return Promise.reject(new GPGMEJS_Error('NOT_YET_IMPLEMENTED'));
        }
        return this.GpgME.encrypt(data, translateKeyInput(publicKeys), wildcard);
    }

    /** Decrypt Message
    * supported
    * TODO: @param {Message} message TODO: for now it accepts an armored string only
    * Unsupported:
    * @param  {String|Array<String>} passwords
    * @param  {Object|Array<Object>} sessionKeys
    * @param  {Date} date

    * TODO
    * @param  {Key|Array<Key>} privateKey
    * @param  {Key|Array<Key>} publicKeys
    * @param  {String} format                    (optional) return data format either as 'utf8' or 'binary'
    * @param  {Signature} signature              (optional) detached signature for verification

    * @returns {Promise<Object>}             decrypted and verified message in the form:
    *                                         { data:Uint8Array|String, filename:String, signatures:[{ keyid:String, valid:Boolean }] }
    * @async
    * @static
    */
    decrypt({ message, privateKeys, passwords, sessionKeys, publicKeys, format='utf8', signature=null, date}) {
        if (passwords !== undefined
            || sessionKeys
            || date){
            return Promise.reject(new GPGMEJS_Error('NOT_IMPLEMENTED'));
        }
        if ( privateKeys
            || publicKeys
            || format !== 'utf8'
            || signature
        ){
            return Promise.reject(new GPGMEJS_Error('NOT_YET_IMPLEMENTED'));
        }
        return this.GpgME.decrypt(message);
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
                return new GPGMEJS_Error; //TODO
            }
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
            return Promise.reject(new GPGMEJS_Error('WRONGPARAM'));
        }
        if ( !key.fingerprint || ! isFingerprint(key.fingerprint)){
            return Promise.reject(new GPGMEJS_Error('WRONGPARAM'));
        }
        let key_to_delete = new GPGME_Key(key.fingerprint);
        return key_to_delete.deleteKey(key.secret);
    }
}

/**
 * TODO error handling.
 * Offers the Key information as the openpgpmode wants
 */
class GPGME_Key_openpgpmode {
    constructor(value){
        this.init = value;
    }

    set init (value){
        if (!this._GPGME_Key && value instanceof GPGME_Key){
            this._GPGME_Key = value;
        } else if (!this._GPGME_Key && isFingerprint(fpr)){
            this._GPGME_Key = new GPGME_Key;
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
 */
function translateKeys(input){
    if (!Array.isArray(input)){
        input = [input];
    }
    let resultset;
    for (let i=0; i< input.length; i++){
        resultset.push(new GPGME_Key_openpgpmode(input[i]));
    }
    return resultset;
}