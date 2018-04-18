import { GPGME_Message } from "./Message";

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

export class Connection{

    /**
     * Opens and closes a port. Thus, it is made sure that the connection can
     * be used.
     * THIS BEHAVIOUR MAY CHANGE!
     * discussion is to keep a port alive as long as the context stays the same
     *
     * TODO returns nothing, but triggers exceptions if not successfull
     */
    constructor(){
        this._connection = chrome.runtime.connectNative('gpgmejson');
        if (!this._connection){
            if (chrome.runtime.lastError){
                throw('NO_CONNECT_RLE');
            } else {
                throw('NO_CONNECT');
            }
        }
        this._flags = {}; // TODO general config
    }

    /**
     * Immediately closes the open port
     */
    disconnect() {
        if (this._connection){
            this._connection.disconnect();
        }
    }

    /**
     * Sends a message and resolves with the answer.
     * @param {GPGME_Message} message
     * @returns {Promise<Object>} the gnupg answer, or rejection with error
     * information
     * TODO: better/more consistent error information
     */
    post(message){
        if (!message || !message instanceof GPGME_Message){
            return Promise.reject('ERR_NO_MSG');
        }
        // let timeout = 5000; //TODO config
        let me = this;
        return new Promise(function(resolve, reject){
            let answer = new Answer(message.op);
            let listener = function(msg) {
                if (!msg){
                    me._connection.onMessage.removeListener(listener)
                    reject('EMPTY_ANSWER');
                } else if (msg.type === "error"){
                    me._connection.onMessage.removeListener(listener)
                    reject(msg.msg);
                } else {
                    answer.add(msg);
                    if (msg.more === true){
                        me._connection.postMessage({'op': 'getmore'});
                    } else {
                        me._connection.onMessage.removeListener(listener)
                        resolve(answer.message);
                    }
                }
            };

            me._connection.onMessage.addListener(listener);
            me._connection.postMessage(message);
            //TBD: needs to be aware if there is a pinentry pending
            // setTimeout(
            //     function(){
            //         me.disconnect();
            //         reject('TIMEOUT');
            //     }, timeout);
        });
     }
};

/**
 * A class for answer objects, checking and processing the return messages of
 * the nativeMessaging communication
 * @param {String} operation The operation, to look up validity of return keys
 */
class Answer{

    constructor(operation){
        this.operation = operation;
    }

    /**
     *
     * @param {Object} msg The message as received with nativeMessaging
     * TODO: "error" and "more" handling are not in here, but in post()
     */
    add(msg){
        if (this._response === undefined){
            this._response = {};
        }
        let messageKeys = Object.keys(msg);
        let poa = permittedOperations[this.operation].answer;
        for (let i= 0; i < messageKeys.length; i++){
            let key = messageKeys[i];
            switch (key) {
                case 'type':
                    if ( msg.type !== 'error' && poa.type.indexOf(msg.type) < 0){
                        console.log( 'unexpected answer type: ' + msg.type);
                        throw('UNEXPECTED_TYPE');

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
                                throw('UNEXPECTED_TYPE');
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
                        console.log('unexpected answer parameter: ' + key);
                        throw('UNEXPECTED_PARAM');
                    }
                    break;
            }
        }
    }

    /**
     * Returns the assembled message. TODO: does not care yet if completed.
     */
    get message(){
        return this._response;
    }
}
