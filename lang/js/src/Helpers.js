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
 * Tries to return an array of fingerprints, either from input fingerprints or
 * from Key objects
 * @param {String|Array<String>} input Input value.
 * @returns {Array<String>} Array of fingerprints.
 */
export function toKeyIdArray(input){
    if (!input){
        return [];
        // TODO: Warning or error here? Did we expect something or is "nothing" okay?
    }
    if (input instanceof Array){
        let result = [];
        for (let i=0; i < input.length; i++){
            if (isFingerprint(input[i]) === true){
                result.push(input[i]);
            } else {
                //TODO error?
                console.log('gpgmejs/Helpers.js Warning: '+
                    input[i] +
                    ' is not a valid key fingerprint and will not be used');
            }
        }
        return result;
    } else if (isFingerprint(input) === true) {
        return [input];
    }
    console.log('gpgmejs/Helpers.js Warning: ' + input +
                    ' is not a valid key fingerprint and will not be used');
    return [];
};

/**
 * check if values are valid hexadecimal values of a specified length
 * @param {*} key input value.
 * @param {int} len the expected length of the value
 */
function hextest(key, len){
    if (!key || typeof(key) !== "string"){
        return false;
    }
    if (key.length !== len){
        return false;
    }
    let regexp= /^[0-9a-fA-F]*$/i;
    return regexp.test(key);
};

/**
 * check if the input is a valid Hex string with a length of 40
 */
export function isFingerprint(string){
    return hextest(string, 40);
};

//TODO needed anywhere?
function isLongId(string){
    return hextest(string, 16);
};

//TODO needed anywhere?
function isShortId(string){
    return hextest(string, 8);
};
