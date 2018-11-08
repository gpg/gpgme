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

import { gpgme_error } from './Errors';

/**
 * Helper function that tries to return an array of fingerprints, either from
 * input fingerprints or from Key objects (openpgp Keys or GPGME_Keys are both
 * accepted).
 *
 * @param {Object | Object[] | String | String[] } input
 * @returns {String[]} Array of fingerprints, or an empty array
 */
export function toKeyIdArray (input){
    if (!input){
        return [];
    }
    if (!Array.isArray(input)){
        input = [input];
    }
    let result = [];
    for (let i=0; i < input.length; i++){
        if (typeof (input[i]) === 'string'){
            if (isFingerprint(input[i]) === true){
                result.push(input[i]);
            } else {
                // MSG_NOT_A_FPR is just a console warning if warning enabled
                // in src/Errors.js
                gpgme_error('MSG_NOT_A_FPR');
            }
        } else if (typeof (input[i]) === 'object'){
            let fpr = '';
            if (input[i].fingerprint !== undefined){
                fpr = input[i].fingerprint;
            } else if (input[i].hasOwnProperty('primaryKey') &&
                input[i].primaryKey.hasOwnProperty('getFingerprint')){
                fpr = input[i].primaryKey.getFingerprint();
            }
            if (isFingerprint(fpr) === true){
                result.push(fpr);
            } else {
                gpgme_error('MSG_NOT_A_FPR');
            }
        } else {
            return gpgme_error('PARAM_WRONG');
        }
    }
    if (result.length === 0){
        return [];
    } else {
        return result;
    }
}

/**
 * Check if values are valid hexadecimal values of a specified length
 * @param {String} key input value.
 * @param {int} len the expected length of the value
 * @returns {Boolean} true if value passes test
 * @private
 */
function hextest (key, len){
    if (!key || typeof (key) !== 'string'){
        return false;
    }
    if (key.length !== len){
        return false;
    }
    let regexp= /^[0-9a-fA-F]*$/i;
    return regexp.test(key);
}

/**
 * Checks if the input is a valid Fingerprint
 *      (Hex string with a length of 40 characters)
 * @param {String} value to check
 * @returns {Boolean} true if value passes test
 */
export function isFingerprint (value){
    return hextest(value, 40);
}

/**
 * check if the input is a valid gnupg long ID (Hex string with a length of 16
 * characters)
 * @param {String} value to check
 * @returns {Boolean} true if value passes test
 */
export function isLongId (value){
    return hextest(value, 16);
}

/**
 * Recursively decodes input (utf8) to output (utf-16; javascript) strings.
 * @param {Object | Array | String} property
 * @private
 */
export function decode (property){
    if (typeof property === 'string'){
        try {
            return decodeURIComponent(escape(unescape(property)));
        }
        catch (error){
            if (error instanceof URIError) {
                return property;
            }
        }
    } else if (Array.isArray(property)){
        let res = [];
        for (let arr=0; arr < property.length; arr++){
            res.push(decode(property[arr]));
        }
        return res;
    } else if (typeof property === 'object'){
        const keys = Object.keys(property);
        if (keys.length){
            let res = {};
            for (let k=0; k < keys.length; k++ ){
                res[keys[k]] = decode(property[keys[k]]);
            }
            return res;
        }
        return property;
    }
    return property;
}

/**
 * Turns a base64 encoded string into an uint8 array
 * adapted from https://gist.github.com/borismus/1032746
 * @param {String} base64 encoded String
 * @returns {Uint8Array}
 * @private
 */
export function atobArray (base64) {
    if (typeof (base64) !== 'string'){
        throw gpgme_error('DECODE_FAIL');
    }
    const raw = window.atob(base64);
    const rawLength = raw.length;
    let array = new Uint8Array(new ArrayBuffer(rawLength));
    for (let i = 0; i < rawLength; i++) {
        array[i] = raw.charCodeAt(i);
    }
    return array;
}

/**
 * Turns a Uint8Array into an utf8-String
 * <pre>
 * Taken and slightly adapted from
 *  https://www.onicos.com/staff/iz/amuse/javascript/expert/utf.txt
 * (original header:
 *   utf.js - UTF-8 <=> UTF-16 conversion
 *
 *   Copyright (C) 1999 Masanao Izumo <iz@onicos.co.jp>
 *   Version: 1.0
 *   LastModified: Dec 25 1999
 *   This library is free.  You can redistribute it and/or modify it.
 *  )
 * </pre>
 * @param {*} array Uint8Array
 * @returns {String}
 * @private
 */
export function Utf8ArrayToStr (array) {
    let out, i, len, c, char2, char3;
    out = '';
    len = array.length;
    i = 0;
    if (array instanceof Uint8Array === false){
        throw gpgme_error('DECODE_FAIL');
    }
    while (i < len) {
        c = array[i++];
        switch (c >> 4) {
        case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:
            // 0xxxxxxx
            out += String.fromCharCode(c);
            break;
        case 12: case 13:
            // 110x xxxx   10xx xxxx
            char2 = array[i++];
            out += String.fromCharCode(((c & 0x1F) << 6) | (char2 & 0x3F));
            break;
        case 14:
            // 1110 xxxx  10xx xxxx  10xx xxxx
            char2 = array[i++];
            char3 = array[i++];
            out += String.fromCharCode(((c & 0x0F) << 12) |
                            ((char2 & 0x3F) << 6) |
                            ((char3 & 0x3F) << 0));
            break;
        default:
            break;
        }
    }
    return out;
}
