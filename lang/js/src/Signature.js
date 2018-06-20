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

/**
 * Validates a signature object and returns
 * @param {Object} sigObject Object as returned by gpgme-json. The definition
 * of the expected values are to be found in the constants 'expKeys', 'expSum',
 * 'expNote' in this file.
 * @returns {GPGME_Signature} Signature Object
 */

import { gpgme_error } from './Errors';

export function createSignature(sigObject){
    if (
        typeof(sigObject) !=='object' ||
        !sigObject.hasOwnProperty('summary') ||
        !sigObject.hasOwnProperty('fingerprint') ||
        !sigObject.hasOwnProperty('timestamp')
        //TODO check if timestamp is mandatory in specification
    ){
        return gpgme_error('SIG_WRONG');
    }
    let keys = Object.keys(sigObject);
    for (let i=0; i< keys.length; i++){
        if ( typeof(sigObject[keys[i]]) !== expKeys[keys[i]] ){
            return gpgme_error('SIG_WRONG');
        }
    }
    let sumkeys = Object.keys(sigObject.summary);
    for (let i=0; i< sumkeys.length; i++){
        if ( typeof(sigObject.summary[sumkeys[i]]) !== expSum[sumkeys[i]] ){
            return gpgme_error('SIG_WRONG');
        }
    }
    if (sigObject.hasOwnProperty('notations')){
        if (!Array.isArray(sigObject.notations)){
            return gpgme_error('SIG_WRONG');
        }
        for (let i=0; i < sigObject.notations.length; i++){
            let notation = sigObject.notations[i];
            let notekeys = Object.keys(notation);
            for (let j=0; j < notekeys.length; j++){
                if ( typeof(notation[notekeys[j]]) !== expNote[notekeys[j]] ){
                    return gpgme_error('SIG_WRONG');
                }
            }
        }
    }
    console.log('sig created');
    return new GPGME_Signature(sigObject);
}


/**
 * Representing the details of a signature. It is supposed to be read-only. The
 * full details as given by gpgme-json can be accessed from the _rawSigObject.
 * )
 */
class GPGME_Signature {
    constructor(sigObject){
        this._rawSigObject = sigObject;
    }

    /**
     * The signatures' fingerprint
     */
    get fingerprint(){
        return this._rawSigObject.fingerprint;
    }

    /**
     * The expiration of this Signature as Javascript date, or null if
     * signature does not expire
     * @returns {Date | null}
     */
    get expiration(){
        if (!this._rawSigObject.exp_timestamp){
            return null;
        }
        return new Date(this._rawSigObject.exp_timestamp* 1000);
    }

    /**
     * The creation date of this Signature in Javascript Date
     * @returns {Date}
     */
    get timestamp(){
        return new Date(this._rawSigObject.timestamp* 1000);
    }

    /**
     * The overall validity of the key. If false, errorDetails may contain
     * additional information
     */
    get valid() {
        if (this._rawSigObject.valid === true){
            return true;
        } else {
            return false;
        }
    }

    /**
     * gives more information on non-valid signatures. Refer to the gpgme docs
     * https://www.gnupg.org/documentation/manuals/gpgme/Verify.html for
     * details on the values
     * @returns {Object} Object with boolean properties
     */
    get errorDetails(){
        let properties = ['revoked', 'key-expired', 'sig-expired',
            'key-missing', 'crl-missing', 'crl-too-old', 'bad-policy',
            'sys-error'];
        let result = {};
        for (let i=0; i< properties.length; i++){
            if ( this._rawSigObject.hasOwnProperty(properties[i]) ){
                result[properties[i]] = this._rawSigObject[properties[i]];
            }
        }
        return result;
    }

}

/**
 * Keys and their value's type for the signature Object
 */
const expKeys = {
    'wrong_key_usage': 'boolean',
    'chain_model': 'boolean',
    'summary': 'object',
    'is_de_vs': 'boolean',
    'status_string':'string',
    'fingerprint':'string',
    'validity_string': 'string',
    'pubkey_algo_name':'string',
    'hash_algo_name':'string',
    'pka_address':'string',
    'status_code':'number',
    'timestamp':'number',
    'exp_timestamp':'number',
    'pka_trust':'number',
    'validity':'number',
    'validity_reason':'number',
    'notations': 'object'
};

/**
 * Keys and their value's type for the summary
 */
const expSum = {
    'valid': 'boolean',
    'green': 'boolean',
    'red': 'boolean',
    'revoked': 'boolean',
    'key-expired': 'boolean',
    'sig-expired': 'boolean',
    'key-missing': 'boolean',
    'crl-missing': 'boolean',
    'crl-too-old': 'boolean',
    'bad-policy': 'boolean',
    'sys-error': 'boolean',
    'sigsum': 'object'
};

/**
 * Keys and their value's type for notations objects
 */
const expNote = {
    'human_readable': 'boolean',
    'critical':'boolean',
    'name': 'string',
    'value': 'string',
    'flags': 'number'
};
