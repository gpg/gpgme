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

import { isFingerprint } from './Helpers'
import { gpgme_error } from './Errors'
import { createMessage } from './Message';
import { permittedOperations } from './permittedOperations';
import { Connection } from './Connection';


export function createKey(fingerprint, parent){
    if (!isFingerprint(fingerprint)){
        return gpgme_error('PARAM_WRONG');
    }
    if ( parent instanceof Connection){
        return new GPGME_Key(fingerprint, parent);
    } else if ( parent.hasOwnProperty('connection') &&
        parent.connection instanceof Connection){
            return new GPGME_Key(fingerprint, parent.connection);
    } else {
        return gpgme_error('PARAM_WRONG');
    }
}

export class GPGME_Key {

    constructor(fingerprint, connection){
        this.fingerprint = fingerprint;
        this.connection = connection;
    }

    set connection(conn){
        if (this._connection instanceof Connection) {
            gpgme_error('CONN_ALREADY_CONNECTED');
        } else if (conn instanceof Connection ) {
            this._connection = conn;
        }
    }

    get connection(){
        if (!this._fingerprint){
            return gpgme_error('KEY_INVALID');
        }
        if (!this._connection instanceof Connection){
            return gpgme_error('CONN_NO_CONNECT');
        } else {
            return this._connection;
        }
    }

    set fingerprint(fpr){
        if (isFingerprint(fpr) === true && !this._fingerprint){
            this._fingerprint = fpr;
        }
    }

    get fingerprint(){
        if (!this._fingerprint){
            return gpgme_error('KEY_INVALID');
        }
        return this._fingerprint;
    }

    /**
     * hasSecret returns true if a secret subkey is included in this Key
     */
    get hasSecret(){
        return this.checkKey('secret');
    }

    get isRevoked(){
        return this.checkKey('revoked');
    }

    get isExpired(){
        return this.checkKey('expired');
    }

    get isDisabled(){
        return this.checkKey('disabled');
    }

    get isInvalid(){
        return this.checkKey('invalid');
    }

    get canEncrypt(){
        return this.checkKey('can_encrypt');
    }

    get canSign(){
        return this.checkKey('can_sign');
    }

    get canCertify(){
        return this.checkKey('can_certify');
    }

    get canAuthenticate(){
        return this.checkKey('can_authenticate');
    }

    get isQualified(){
        return this.checkKey('is_qualified');
    }

    get armored(){
        let msg = createMessage ('export_key');
        msg.setParameter('armor', true);
        if (msg instanceof Error){
            return gpgme_error('KEY_INVALID');
        }
        this.connection.post(msg).then(function(result){
            return result.data;
        });
        // TODO return value not yet checked. Should result in an armored block
        // in correct encoding
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
        return this.checkKey('subkeys').then(function(result){
            // TBD expecting a list of fingerprints
            if (!Array.isArray(result)){
                result = [result];
            }
            let resultset = [];
            for (let i=0; i < result.length; i++){
                let subkey = new GPGME_Key(result[i], this.connection);
                if (subkey instanceof GPGME_Key){
                    resultset.push(subkey);
                }
            }
            return Promise.resolve(resultset);
        }, function(error){
            //TODO this.checkKey fails
        });
    }

    /**
     * creation time stamp of the key
     * @returns {Date|null} TBD
     */
    get timestamp(){
        return this.checkKey('timestamp');
        //TODO GPGME: -1 if the timestamp is invalid, and 0 if it is not available.
    }

    /**
     * The expiration timestamp of this key TBD
     *  @returns {Date|null} TBD
     */
    get expires(){
        return this.checkKey('expires');
        // TODO convert to Date; check for 0
    }

    /**
     * getter name TBD
     * @returns {String|Array<String>} The user ids associated with this key
     */
    get userIds(){
        return this.checkKey('uids');
    }

    /**
     * @returns {String} The public key algorithm supported by this subkey
     */
    get pubkey_algo(){
        return this.checkKey('pubkey_algo');
    }

    /**
    * generic function to query gnupg information on a key.
    * @param {*} property The gpgme-json property to check.
    * TODO: check if Promise.then(return)
    */
    checkKey(property){
        if (!this._fingerprint){
            return gpgme_error('KEY_INVALID');
        }
        return gpgme_error('NOT_YET_IMPLEMENTED');
        // TODO: async is not what is to be ecpected from Key information :(
        if (!property || typeof(property) !== 'string' ||
            !permittedOperations['keyinfo'].hasOwnProperty(property)){
            return gpgme_error('PARAM_WRONG');
        }
        let msg = createMessage ('keyinfo');
        if (msg instanceof Error){
            return gpgme_error('PARAM_WRONG');
        }
        msg.setParameter('fingerprint', this.fingerprint);
        this.connection.post(msg).then(function(result, error){
            if (error){
                return gpgme_error('GNUPG_ERROR',error.msg);
            } else if (result.hasOwnProperty(property)){
                return result[property];
            }
            else if (property == 'secret'){
                // TBD property undefined means "not true" in case of secret?
                return false;
            } else {
                return gpgme_error('CONN_UNEXPECTED_ANSWER');
            }
        }, function(error){
            return gpgme_error('GENERIC_ERROR');
        });
    }
};