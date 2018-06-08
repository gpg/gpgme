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

import { permittedOperations } from './permittedOperations';
import { gpgme_error } from './Errors';
import { Connection } from './Connection';

export function createMessage(operation){
    if (typeof(operation) !== 'string'){
        return gpgme_error('PARAM_WRONG');
    }
    if (permittedOperations.hasOwnProperty(operation)){
        return new GPGME_Message(operation);
    } else {
        return gpgme_error('MSG_WRONG_OP');
    }
}

/**
 * Prepares a communication request. It checks operations and parameters in
 * ./permittedOperations.
 * @param {String} operation
 */
export class GPGME_Message {
    //TODO getter

    constructor(operation){
        this.operation = operation;
    }

    set operation (op){
        if (typeof(op) === 'string'){
            if (!this._msg){
                this._msg = {};
            }
            if (!this._msg.op & permittedOperations.hasOwnProperty(op)){
                this._msg.op = op;
            }
        }
    }
    get operation(){
        return this._msg.op;
    }

    /**
     * Set the maximum size of responses from gpgme in bytes. Values allowed
     * range from 10kB to 1MB. The lower limit is arbitrary, the upper limit
     * fixed by browsers' nativeMessaging specifications
     */
    set chunksize(value){
        if (
            Number.isInteger(value) &&
            value > 10 * 1024 &&
            value <= 1024 * 1024
        ){
            this._chunksize = value;
        }
    }
    get chunksize(){
        if (this._chunksize === undefined){
            return 1024 * 1023;
        } else {
            return this._chunksize;
        }
    }

    /**
     * If expect is set to 'base64', the response is expected to be base64
     * encoded binary
     */
    set expect(value){
        if (value ==='base64'){
            this._expect = value;
        }
    }

    get expect(){
        if ( this._expect === 'base64'){
            return this._expect;
        }
        return undefined;
    }


    /**
     * Sets a parameter for the message. Note that the operation has to be set
     * first, to be able to check if the parameter is permittted
     * @param {String} param Parameter to set
     * @param {any} value Value to set //TODO: Some type checking
     * @returns {Boolean} If the parameter was set successfully
     */
    setParameter(param,value){
        if (!param || typeof(param) !== 'string'){
            return gpgme_error('PARAM_WRONG');
        }
        let po = permittedOperations[this._msg.op];
        if (!po){
            return gpgme_error('MSG_WRONG_OP');
        }
        let poparam = null;
        if (po.required.hasOwnProperty(param)){
            poparam = po.required[param];
        } else if (po.optional.hasOwnProperty(param)){
            poparam = po.optional[param];
        } else {
            return gpgme_error('PARAM_WRONG');
        }
        let checktype = function(val){
            switch(typeof(val)){
            case 'string':
                if (poparam.allowed.indexOf(typeof(val)) >= 0
                        && val.length > 0) {
                    return true;
                }
                return gpgme_error('PARAM_WRONG');
            case 'number':
                if (
                    poparam.allowed.indexOf('number') >= 0
                        && isNaN(value) === false){
                    return true;
                }
                return gpgme_error('PARAM_WRONG');

            case 'boolean':
                if (poparam.allowed.indexOf('boolean') >= 0){
                    return true;
                }
                return gpgme_error('PARAM_WRONG');
            case 'object':
                if (Array.isArray(val)){
                    if (poparam.array_allowed !== true){
                        return gpgme_error('PARAM_WRONG');
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
                    return gpgme_error('PARAM_WRONG');
                } else {
                    return gpgme_error('PARAM_WRONG');
                }
                break;
            default:
                return gpgme_error('PARAM_WRONG');
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
     * Check if the message has the minimum requirements to be sent, according
     * to the definitions in permittedOperations
     * @returns {Boolean}
     */
    get isComplete(){
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
     * Returns the prepared message with parameters and completeness checked
     * @returns {Object|null} Object to be posted to gnupg, or null if
     * incomplete
     */
    get message(){
        if (this.isComplete === true){
            this._msg.chunksize = this.chunksize;
            return this._msg;
        }
        else {
            return null;
        }

    }

    post(){
        let me = this;
        return new Promise(function(resolve, reject) {
            if (me.isComplete === true) {
                let conn  = new Connection;
                if (me._msg.chunksize === undefined){
                    me._msg.chunksize = 1023*1024;
                }
                conn.post(me).then(function(response) {
                    resolve(response);
                }, function(reason) {
                    reject(reason);
                });
            }
            else {
                reject(gpgme_error('MSG_INCOMPLETE'));
            }
        });
    }
}
