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

/* global chrome */

import { permittedOperations } from './permittedOperations';
import { gpgme_error } from './Errors';
import { GPGME_Message, createMessage } from './Message';

/**
 * A Connection handles the nativeMessaging interaction.
 */
export class Connection{

    constructor(){
        this.connect();
    }

    /**
     * Retrieves the information about the backend.
     * @param {Boolean} details (optional) If set to false, the promise will
     *  just return a connection status
     * @returns {Promise<Object>} result
     * @returns {String} result.gpgme Version number of gpgme
     * @returns {Array<Object>} result.info Further information about the
     * backends.
     *      Example:
     *          "protocol":     "OpenPGP",
     *          "fname":        "/usr/bin/gpg",
     *          "version":      "2.2.6",
     *          "req_version":  "1.4.0",
     *          "homedir":      "default"
     */
    checkConnection(details = true){
        if (details === true) {
            return this.post(createMessage('version'));
        } else {
            let me = this;
            return new Promise(function(resolve) {
                Promise.race([
                    me.post(createMessage('version')),
                    new Promise(function(resolve, reject){
                        setTimeout(function(){
                            reject(gpgme_error('CONN_TIMEOUT'));
                        }, 500);
                    })
                ]).then(function(){ // success
                    resolve(true);
                }, function(){ // failure
                    resolve(false);
                });
            });
        }
    }

    /**
     * Immediately closes the open port.
     */
    disconnect() {
        if (this._connection){
            this._connection.disconnect();
            this._connection = null;
        }
    }

    /**
     * Opens a nativeMessaging port.
     */
    connect(){
        if (!this._connection){
            this._connection = chrome.runtime.connectNative('gpgmejson');
        }
    }

    /**
     * Sends a message and resolves with the answer.
     * @param {GPGME_Message} message
     * @returns {Promise<Object>} the gnupg answer, or rejection with error
     * information.
     */
    post(message){
        if (!message || !(message instanceof GPGME_Message)){
            this.disconnect();
            return Promise.reject(gpgme_error(
                'PARAM_WRONG', 'Connection.post'));
        }
        if (message.isComplete !== true){
            this.disconnect();
            return Promise.reject(gpgme_error('MSG_INCOMPLETE'));
        }
        let me = this;
        let chunksize = message.chunksize;
        return new Promise(function(resolve, reject){
            let answer = new Answer(message);
            let listener = function(msg) {
                if (!msg){
                    me._connection.onMessage.removeListener(listener);
                    me._connection.disconnect();
                    reject(gpgme_error('CONN_EMPTY_GPG_ANSWER'));
                } else {
                    let answer_result = answer.collect(msg);
                    if (answer_result !== true){
                        me._connection.onMessage.removeListener(listener);
                        me._connection.disconnect();
                        reject(answer_result);
                    } else {
                        if (msg.more === true){
                            me._connection.postMessage({
                                'op': 'getmore',
                                'chunksize': chunksize
                            });
                        } else {
                            me._connection.onMessage.removeListener(listener);
                            me._connection.disconnect();
                            if (answer.message instanceof Error){
                                reject(answer.message);
                            } else {
                                resolve(answer.message);
                            }
                        }
                    }
                }
            };
            me._connection.onMessage.addListener(listener);
            if (permittedOperations[message.operation].pinentry){
                return me._connection.postMessage(message.message);
            } else {
                return Promise.race([
                    me._connection.postMessage(message.message),
                    function(resolve, reject){
                        setTimeout(function(){
                            me._connection.disconnect();
                            reject(gpgme_error('CONN_TIMEOUT'));
                        }, 5000);
                    }]).then(function(result){
                    return result;
                }, function(reject){
                    if(!(reject instanceof Error)) {
                        me._connection.disconnect();
                        return gpgme_error('GNUPG_ERROR', reject);
                    } else {
                        return reject;
                    }
                });
            }
        });
    }
}

/**
 * A class for answer objects, checking and processing the return messages of
 * the nativeMessaging communication.
 * @param {String} operation The operation, to look up validity of returning
 * messages
 */
class Answer{

    constructor(message){
        this.operation = message.operation;
        this.expect = message.expect;
    }

    collect(msg){
        if (typeof(msg) !== 'object' || !msg.hasOwnProperty('response')) {
            return gpgme_error('CONN_UNEXPECTED_ANSWER');
        }
        if (this._responseb64 === undefined){
            //this._responseb64 = [msg.response];
            this._responseb64 = msg.response;
            return true;
        } else {
            //this._responseb64.push(msg.response);
            this._responseb64 += msg.response;
            return true;
        }
    }

    get message(){
        if (this._responseb64 === undefined){
            return gpgme_error('CONN_UNEXPECTED_ANSWER');
        }
        // let _decodedResponse = JSON.parse(atob(this._responseb64.join('')));
        let _decodedResponse = JSON.parse(atob(this._responseb64));
        let _response = {};
        let messageKeys = Object.keys(_decodedResponse);
        let poa = permittedOperations[this.operation].answer;
        if (messageKeys.length === 0){
            return gpgme_error('CONN_UNEXPECTED_ANSWER');
        }
        for (let i= 0; i < messageKeys.length; i++){
            let key = messageKeys[i];
            switch (key) {
            case 'type':
                if (_decodedResponse.type === 'error'){
                    return (gpgme_error('GNUPG_ERROR', _decodedResponse.msg));
                } else if (poa.type.indexOf(_decodedResponse.type) < 0){
                    return gpgme_error('CONN_UNEXPECTED_ANSWER');
                }
                break;
            case 'base64':
                break;
            case 'msg':
                if (_decodedResponse.type === 'error'){
                    return (gpgme_error('GNUPG_ERROR', _decodedResponse.msg));
                }
                break;
            default:
                if (!poa.data.hasOwnProperty(key)){
                    return gpgme_error('CONN_UNEXPECTED_ANSWER');
                }
                if( typeof(_decodedResponse[key]) !== poa.data[key] ){
                    return gpgme_error('CONN_UNEXPECTED_ANSWER');
                }
                if (_decodedResponse.base64 === true
                    && poa.data[key] === 'string'
                    && this.expect === undefined
                ){
                    _response[key] = decodeURIComponent(
                        atob(_decodedResponse[key]).split('').map(
                            function(c) {
                                return '%' +
                            ('00' + c.charCodeAt(0).toString(16)).slice(-2);
                            }).join(''));
                } else {
                    _response[key] = _decodedResponse[key];
                }
                break;
            }
        }
        return _response;
    }
}
