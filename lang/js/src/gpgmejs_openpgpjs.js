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
// import {Keyring}  from "./Keyring" TODO


export class GpgME_openPGPCompatibility {

    constructor(){
        this._gpgme =  new GpgME;
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
            throw('NOT_IMPLEMENTED');
        }
        if ( privateKeys
            || filename
            || compression
            || armor === false
            || detached == true){
                console.log('may be implemented later');
                throw('NOT_YET_IMPLEMENTED');
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

            throw('NOT_IMPLEMENTED');
        }
        if ( privateKeys
            || publicKeys
            || format !== 'utf8'
            || signature
        ){
            console.log('may be implemented later');
            throw('NOT_YET_IMPLEMENTED');
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
 *
 * @param {Object | String} Key Either a (presumably openpgp Key) Object with a
 *      primaryKeyproperty and a method getFingerprint, or a string.
 * @returns {String} Unchecked string value claiming to be a fingerprint
 *      TODO: gpgmejs checks again, so it's okay here.
 */
function translateKeyInput(Key){
    if (!Key){
        return [];
    }
    if (!Array.isArray(Key)){
        Key = [Key];
    }
    let resultslist = [];
    for (let i=0; i < Key.length; i++){
        if (typeof(Key[i]) === 'string'){
            resultslist.push(Key);
        } else if (
            Key[i].hasOwnProperty(primaryKey) &&
            Key[i].primaryKey.hasOwnProperty(getFingerprint)){
                resultslist.push(Key[i].primaryKey.getFingerprint());
        }
    }
    return resultslist;
}