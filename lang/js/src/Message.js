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
import { permittedOperations } from './permittedOperations'
import { gpgme_error } from './Errors'
export class GPGME_Message {
    //TODO getter

    constructor(operation){
        setOperation(this, operation);
    }

    get operation(){
        return this._msg.op;
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
        if (!this._msg || !this._msg.op){
            return gpgme_error('MSG_OP_PENDING');
        }
        let po = permittedOperations[this._msg.op];
        if (!po){
            return gpgme_error('MSG_WRONG_OP');
        }
        if (po.required.indexOf(param) >= 0 || po.optional.indexOf(param) >= 0){
            this._msg[param] = value;
            return true;
        }
        return gpgme_error('PARAM_WRONG');
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
        let reqParams = permittedOperations[this._msg.op].required;
        for (let i=0; i < reqParams.length; i++){

            if (!this._msg.hasOwnProperty(reqParams[i])){
                console.log(reqParams[i] + 'missing');
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
            return this._msg;
        }
        else {
            return null;
        }

    }
}

/**
 * Defines the operation this message will have
 * @param {String} operation Must be defined in permittedOperations
 *  TODO: move to constructor?
 */
function setOperation (scope, operation){
    if (!operation || typeof(operation) !== 'string'){
        return gpgme_error('PARAM_WRONG');
    }
    if (permittedOperations.hasOwnProperty(operation)){
        if (!scope._msg){
            scope._msg = {};
        }
        scope._msg.op = operation;
    } else {
        return gpgme_error('MSG_WRONG_OP');
    }
}