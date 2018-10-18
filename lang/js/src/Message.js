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

import { permittedOperations } from './permittedOperations';
import { gpgme_error } from './Errors';
import { Connection } from './Connection';

/**
 * Initializes a message for gnupg, validating the message's purpose with
 *   {@link permittedOperations} first
 * @param {String} operation
 * @returns {GPGME_Message} The Message object
 */
export function createMessage (operation){
    if (typeof (operation) !== 'string'){
        throw gpgme_error('PARAM_WRONG');
    }
    if (permittedOperations.hasOwnProperty(operation)){
        return new GPGME_Message(operation);
    } else {
        throw gpgme_error('MSG_WRONG_OP');
    }
}

/**
 * A Message collects, validates and handles all information required to
 * successfully establish a meaningful communication with gpgme-json via
 * [Connection.post]{@link Connection#post}. The definition on which
 * communication is available can be found in {@link permittedOperations}.
 * @class
 * @protected
 */
export class GPGME_Message {

    constructor (operation){
        this._msg = {
            op: operation,
            chunksize: 1023* 1024
        };
        this._expected = null;
    }

    get operation (){
        return this._msg.op;
    }

    set expected (value){
        if (value === 'uint8' || value === 'base64'){
            this._expected = value;
        }
    }

    get expected () {
        return this._expected;
    }
    /**
     * The maximum size of responses from gpgme in bytes. As of September 2018,
     * most browsers will only accept answers up to 1 MB of size.
     * Everything above that threshold will not pass through
     * nativeMessaging; answers that are larger need to be sent in parts.
     * The lower limit is set to 10 KB. Messages smaller than the threshold
     * will not encounter problems, larger messages will be received in
     * chunks. If the value is not explicitly specified, 1023 KB is used.
     */
    set chunksize (value){
        if (
            Number.isInteger(value) &&
            value > 10 * 1024 &&
            value <= 1024 * 1024
        ){
            this._msg.chunksize = value;
        }
    }

    get chunksize (){
        return this._msg.chunksize;
    }

    /**
     * Returns the prepared message after their parameters and the completion
     * of required parameters have been checked.
     * @returns {Object|null} Object to be posted to gnupg, or null if
     * incomplete
     */
    get message () {
        if (this.isComplete() === true){
            return this._msg;
        } else {
            return null;
        }
    }

    /**
     * Sets a parameter for the message. It validates with
     * {@link permittedOperations}
     * @param {String} param Parameter to set
     * @param {any} value Value to set
     * @returns {Boolean} True if the parameter was set successfully.
     * Throws errors if the parameters don't match the message operation
     */
    setParameter ( param,value ){
        if (!param || typeof (param) !== 'string'){
            throw gpgme_error('PARAM_WRONG');
        }
        let po = permittedOperations[this._msg.op];
        if (!po){
            throw gpgme_error('MSG_WRONG_OP');
        }
        let poparam = null;
        if (po.required.hasOwnProperty(param)){
            poparam = po.required[param];
        } else if (po.optional.hasOwnProperty(param)){
            poparam = po.optional[param];
        } else {
            throw gpgme_error('PARAM_WRONG');
        }
        // check incoming value for correctness
        let checktype = function (val){
            switch (typeof (val)){
            case 'string':
                if (poparam.allowed.indexOf(typeof (val)) >= 0
                        && val.length > 0) {
                    return true;
                }
                throw gpgme_error('PARAM_WRONG');
            case 'number':
                if (
                    poparam.allowed.indexOf('number') >= 0
                        && isNaN(value) === false){
                    return true;
                }
                throw gpgme_error('PARAM_WRONG');

            case 'boolean':
                if (poparam.allowed.indexOf('boolean') >= 0){
                    return true;
                }
                throw gpgme_error('PARAM_WRONG');
            case 'object':
                if (Array.isArray(val)){
                    if (poparam.array_allowed !== true){
                        throw gpgme_error('PARAM_WRONG');
                    }
                    for (let i=0; i < val.length; i++){
                        let res = checktype(val[i]);
                        if (res !== true){
                            return res;
                        }
                    }
                    if (val.length > 0) {
                        return true;
                    }
                } else if (val instanceof Uint8Array){
                    if (poparam.allowed.indexOf('Uint8Array') >= 0){
                        return true;
                    }
                    throw gpgme_error('PARAM_WRONG');
                } else {
                    throw gpgme_error('PARAM_WRONG');
                }
                break;
            default:
                throw gpgme_error('PARAM_WRONG');
            }
        };
        let typechecked = checktype(value);
        if (typechecked !== true){
            return typechecked;
        }
        if (poparam.hasOwnProperty('allowed_data')){
            if (poparam.allowed_data.indexOf(value) < 0){
                return gpgme_error('PARAM_WRONG');
            }
        }
        this._msg[param] = value;
        return true;
    }


    /**
     * Check if the message has the minimum requirements to be sent, that is
     * all 'required' parameters according to {@link permittedOperations}.
     * @returns {Boolean} true if message is complete.
     */
    isComplete (){
        if (!this._msg.op){
            return false;
        }
        let reqParams = Object.keys(
            permittedOperations[this._msg.op].required);
        let msg_params = Object.keys(this._msg);
        for (let i=0; i < reqParams.length; i++){
            if (msg_params.indexOf(reqParams[i]) < 0){
                return false;
            }
        }
        return true;
    }

    /**
     * Sends the Message via nativeMessaging and resolves with the answer.
     * @returns {Promise<Object>} GPGME response
     * @async
     */
    post (){
        let me = this;
        return new Promise(function (resolve, reject) {
            if (me.isComplete() === true) {

                let conn  = new Connection;
                conn.post(me).then(function (response) {
                    resolve(response);
                }, function (reason) {
                    reject(reason);
                });
            }
            else {
                reject(gpgme_error('MSG_INCOMPLETE'));
            }
        });
    }

}
