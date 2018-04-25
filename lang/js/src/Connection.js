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
 * A connection port will be opened for each communication between gpgmejs and
 * gnupg. It should be alive as long as there are additional messages to be
 * expected.
 */
import { permittedOperations } from './permittedOperations'
import { GPGMEJS_Error } from "./Errors"
import { GPGME_Message } from "./Message";

/**
 * A Connection handles the nativeMessaging interaction.
 */
export class Connection{

    constructor(){
        this.connect();
        let me = this;
    }

    /**
     * (Simple) Connection check.
     * @returns {Boolean} true if the onDisconnect event has not been fired.
     * Please note that the event listener of the port takes some time
     * (5 ms seems enough) to react after the port is created. Then this will
     * return undefined
     */
    get isConnected(){
        return this._isConnected;
    }

    /**
     * Immediately closes the open port.
     */
    disconnect() {
        if (this._connection){
            this._connection.disconnect();
        }
    }

    /**
     * Opens a nativeMessaging port.
     */
    connect(){
        if (this._isConnected === true){
            GPGMEJS_Error('CONN_ALREADY_CONNECTED');
        } else {
            this._isConnected = true;
            this._connection = chrome.runtime.connectNative('gpgmejson');
            let me = this;
            this._connection.onDisconnect.addListener(
                function(){
                    me._isConnected = false;
                }
            );
        }
    }

    /**
     * Sends a message and resolves with the answer.
     * @param {GPGME_Message} message
     * @returns {Promise<Object>} the gnupg answer, or rejection with error
     * information.
     */
    post(message){
        if (!this.isConnected){
            return Promise.reject(GPGMEJS_Error('CONN_NO_CONNECT'));
        }
        if (!message || !message instanceof GPGME_Message){
            return Promise.reject(GPGMEJS_Error('PARAM_WRONG'), message);
        }
        if (message.isComplete !== true){
            return Promise.reject(GPGMEJS_Error('MSG_INCOMPLETE'));
        }
        let me = this;
        return new Promise(function(resolve, reject){
            let answer = new Answer(message.operation);
            let listener = function(msg) {
                if (!msg){
                    me._connection.onMessage.removeListener(listener)
                    reject(GPGMEJS_Error('CONN_EMPTY_GPG_ANSWER'));
                } else if (msg.type === "error"){
                    me._connection.onMessage.removeListener(listener)
                    reject(
                        {code: 'GNUPG_ERROR',
                         msg: msg.msg} );
                } else {
                    let answer_result = answer.add(msg);
                    if (answer_result !== true){
                        reject(answer_result);
                    }
                    if (msg.more === true){
                        me._connection.postMessage({'op': 'getmore'});
                    } else {
                        me._connection.onMessage.removeListener(listener)
                        resolve(answer.message);
                    }
                }
            };

            me._connection.onMessage.addListener(listener);
            me._connection.postMessage(message.message);

            //TBD: needs to be aware if there is a pinentry pending
            // setTimeout(
            //     function(){
            //         me.disconnect();
            //         reject(GPGMEJS_Error('CONN_TIMEOUT'));
            //     }, timeout);
        });
     }
};

/**
 * A class for answer objects, checking and processing the return messages of
 * the nativeMessaging communication.
 * @param {String} operation The operation, to look up validity of returning messages
 */
class Answer{

    constructor(operation){
        this.operation = operation;
    }

    /**
     * Add the information to the answer
     * @param {Object} msg The message as received with nativeMessaging
     * returns true if successfull, GPGMEJS_Error otherwise
     */
    add(msg){
        if (this._response === undefined){
            this._response = {};
        }
        let messageKeys = Object.keys(msg);
        let poa = permittedOperations[this.operation].answer;
        if (messageKeys.length === 0){
            return GPGMEJS_Error('CONN_UNEXPECTED_ANSWER');
        }
        for (let i= 0; i < messageKeys.length; i++){
            let key = messageKeys[i];
            switch (key) {
                case 'type':
                    if ( msg.type !== 'error' && poa.type.indexOf(msg.type) < 0){
                        return GPGMEJS_Error('CONN_UNEXPECTED_ANSWER');
                    }
                    break;
                case 'more':
                    break;
                default:
                    //data should be concatenated
                    if (poa.data.indexOf(key) >= 0){
                        if (!this._response.hasOwnProperty(key)){
                            this._response[key] = '';
                        }
                        this._response[key] = this._response[key].concat(msg[key]);
                    }
                    //params should not change through the message
                    else if (poa.params.indexOf(key) >= 0){
                        if (!this._response.hasOwnProperty(key)){
                            this._response[key] = msg[key];
                        }
                        else if (this._response[key] !== msg[key]){
                                return GPGMEJS_Error('CONN_UNEXPECTED_ANSWER',msg[key]);
                        }
                    }
                    //infos may be json objects etc. Not yet defined.
                    // Pushing them into arrays for now
                    else if (poa.infos.indexOf(key) >= 0){
                        if (!this._response.hasOwnProperty(key)){
                            this._response[key] = [];
                        }
                        this._response.push(msg[key]);
                    }
                    else {
                        return GPGMEJS_Error('CONN_UNEXPECTED_ANSWER', key);
                    }
                    break;
            }
        }
        return true;
    }

    /**
     * @returns {Object} the assembled message.
     * TODO: does not care yet if completed.
     */
    get message(){
        return this._response;
    }
}
