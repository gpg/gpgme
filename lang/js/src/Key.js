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
 * The key class allows to query the information defined in gpgme Key Objects
 * (see https://www.gnupg.org/documentation/manuals/gpgme/Key-objects.html)
 *
 * This is a stub, as the gpgme-json side is not yet implemented
 *
 */

import {isFingerprint} from './Helpers'
import {GPGMEJS_Error} from './Errors'

export class GPGME_Key {

    constructor(fingerprint){
        if (isFingerprint(fingerprint) === true){
            this._fingerprint = fingerprint;
        } else {
            return new GPGMEJS_Error('WRONGPARAM', 'Key.js: invalid fingerprint');
        }
    }

    get fingerprint(){
        return this._fingerprint;
    }

    /**
     * hasSecret returns true if a secret subkey is included in this Key
     */
    get hasSecret(){
        checkKey(this._fingerprint, 'secret').then( function(result){
            return Promise.resolve(result);
        });

    }

    get isRevoked(){
        return checkKey(this._fingerprint, 'revoked');
    }

    get isExpired(){
        return checkKey(this._fingerprint, 'expired');
    }

    get isDisabled(){
        return checkKey(this._fingerprint, 'disabled');
    }

    get isInvalid(){
        return checkKey(this._fingerprint, 'invalid');
    }

    get canEncrypt(){
        return checkKey(this._fingerprint, 'can_encrypt');
    }

    get canSign(){
        return checkKey(this._fingerprint, 'can_sign');
    }

    get canCertify(){
        return checkKey(this._fingerprint, 'can_certify');
    }

    get canAuthenticate(){
        return checkKey(this._fingerprint, 'can_authenticate');
    }

    get isQualified(){
        return checkKey(this._fingerprint, 'is_qualified');
    }

    get armored(){
        let me = this;
        return new Promise(function(resolve, reject){
            let conn = new Connection();
            conn.setFlag('armor', true);
            conn.post('export',{'fpr': me._fingerprint});
        });
        // TODO return value not yet checked. Should result in an armored block
        // in correct encoding
        // TODO openpgpjs also returns secKey if private = true?
    }

    /**
     * TODO returns true if this is the default key used to sign
     */
    get isDefault(){
        throw('NOT_YET_IMPLEMENTED');
    }

    /**
     * get the Key's subkeys as GPGME_Key objects
     * @returns {Array<GPGME_Key>}
     */
    get subkeys(){
        return checkKey(this._fingerprint, 'subkeys').then(function(result){
            // TBD expecting a list of fingerprints
            if (!Array.isArray(result)){
                result = [result];
            }
            let resultset = [];
            for (let i=0; i < result.length; i++){
                let subkey = new GPGME_Key(result[i]);
                if (subkey instanceof GPGME_Key){
                    resultset.push(subkey);
                }
            }
            return Promise.resolve(resultset);
        });
    }

    /**
     * creation time stamp of the key
     * @returns {Date|null} TBD
     */
    get timestamp(){
        return checkKey(this._fingerprint, 'timestamp');
        //TODO GPGME: -1 if the timestamp is invalid, and 0 if it is not available.
    }

    /**
     * The expiration timestamp of this key TBD
     *  @returns {Date|null} TBD
     */
    get expires(){
        return checkKey(this._fingerprint, 'expires');
        // TODO convert to Date; check for 0
    }

    /**
     * getter name TBD
     * @returns {String|Array<String>} The user ids associated with this key
     */
    get userIds(){
        return checkKey(this._fingerprint, 'uids');
    }

    /**
     * @returns {String} The public key algorithm supported by this subkey
     */
    get pubkey_algo(){
        return checkKey(this._fingerprint, 'pubkey_algo');
    }
};

/**
 * generic function to query gnupg information on a key.
 * @param {*} fingerprint The identifier of the Keyring
 * @param {*} property The gpgme-json property to check
 *
 */
function checkKey(fingerprint, property){
    return Promise.reject(new GPGMEJS_Error('NOT_YET_IMPLEMENTED'));

    return new Promise(function(resolve, reject){
        if (!isFingerprint(fingerprint)){
            reject('not a fingerprint'); //TBD
        }
        let conn = new Connection();
        conn.post('getkey',{ // TODO not yet implemented in gpgme
            'fingerprint': this.fingerprint})
        .then(function(result){
            if (property !== undefined){
                if (result.hasOwnProperty(key)){
                    resolve(result[property]);
                }
                else if (property == 'secret'){
                    // property undefined means "not true" in case of secret
                    resolve(false);
                } else {
                    reject('ERR_INVALID_PROPERTY') //TBD
                }
            }


            resolve(result);
        }, function(error){
            reject(error);
        });
    });
};