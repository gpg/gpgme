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
import { decode } from './Helpers';

/**
 * A Connection handles the nativeMessaging interaction via a port. As the
 * protocol only allows up to 1MB of message sent from the nativeApp to the
 * browser, the connection will stay open until all parts of a communication
 * are finished. For a new request, a new port will open, to avoid mixing
 * contexts.
 * @class
 */
export class Connection{

    constructor(){
        let _connection = chrome.runtime.connectNative('gpgmejson');


        /**
         * Immediately closes an open port.
         */
        this.disconnect = function () {
            if (_connection){
                _connection.disconnect();
                _connection = null;
            }
        };


        /**
        * @typedef {Object} backEndDetails
        * @property {String} gpgme Version number of gpgme
        * @property {Array<Object>} info Further information about the backend
        * and the used applications (Example:
        * {
        *          "protocol":     "OpenPGP",
        *          "fname":        "/usr/bin/gpg",
        *          "version":      "2.2.6",
        *          "req_version":  "1.4.0",
        *          "homedir":      "default"
        * }
        */

        /**
         * Retrieves the information about the backend.
         * @param {Boolean} details (optional) If set to false, the promise will
         *  just return if a connection was successful.
         * @returns {Promise<backEndDetails>|Promise<Boolean>} Details from the
         * backend
         * @async
         */
        this.checkConnection = function(details = true){
            const msg = createMessage('version');
            if (details === true) {
                return this.post(msg);
            } else {
                let me = this;
                return new Promise(function(resolve) {
                    Promise.race([
                        me.post(msg),
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
        };

        /**
         * Sends a {@link GPGME_Message} via tghe nativeMessaging port. It
         * resolves with the completed answer after all parts have been
         * received and reassembled, or rejects with an {@link GPGME_Error}.
         *
         * @param {GPGME_Message} message
         * @returns {Promise<Object>} The collected answer
         * @async
         */
        this.post = function (message){
            if (!message || !(message instanceof GPGME_Message)){
                this.disconnect();
                return Promise.reject(gpgme_error(
                    'PARAM_WRONG', 'Connection.post'));
            }
            if (message.isComplete() !== true){
                this.disconnect();
                return Promise.reject(gpgme_error('MSG_INCOMPLETE'));
            }
            let chunksize = message.chunksize;
            return new Promise(function(resolve, reject){
                let answer = Object.freeze(new Answer(message));
                let listener = function(msg) {
                    if (!msg){
                        _connection.onMessage.removeListener(listener);
                        _connection.disconnect();
                        reject(gpgme_error('CONN_EMPTY_GPG_ANSWER'));
                    } else {
                        let answer_result = answer.collect(msg);
                        if (answer_result !== true){
                            _connection.onMessage.removeListener(listener);
                            _connection.disconnect();
                            reject(answer_result);
                        } else {
                            if (msg.more === true){
                                _connection.postMessage({
                                    'op': 'getmore',
                                    'chunksize': chunksize
                                });
                            } else {
                                _connection.onMessage.removeListener(listener);
                                _connection.disconnect();
                                const message = answer.getMessage();
                                if (message instanceof Error){
                                    reject(message);
                                } else {
                                    resolve(message);
                                }
                            }
                        }
                    }
                };
                _connection.onMessage.addListener(listener);
                if (permittedOperations[message.operation].pinentry){
                    return _connection.postMessage(message.message);
                } else {
                    return Promise.race([
                        _connection.postMessage(message.message),
                        function(resolve, reject){
                            setTimeout(function(){
                                _connection.disconnect();
                                reject(gpgme_error('CONN_TIMEOUT'));
                            }, 5000);
                        }]).then(function(result){
                        return result;
                    }, function(reject){
                        if(!(reject instanceof Error)) {
                            _connection.disconnect();
                            return gpgme_error('GNUPG_ERROR', reject);
                        } else {
                            return reject;
                        }
                    });
                }
            });
        };
    }
}

/**
 * A class for answer objects, checking and processing the return messages of
 * the nativeMessaging communication.
 * @protected
 */
class Answer{

    /**
     * @param {GPGME_Message} message
     */
    constructor(message){
        const operation = message.operation;
        const expected = message.getExpect();
        let response_b64 = null;

        this.getOperation = function(){
            return operation;
        };

        this.getExpect = function(){
            return expected;
        };

        /**
         * Adds incoming base64 encoded data to the existing response
         * @param {*} msg base64 encoded data.
         * @returns {Boolean}
         *
         * @private
         */
        this.collect = function (msg){
            if (typeof(msg) !== 'object' || !msg.hasOwnProperty('response')) {
                return gpgme_error('CONN_UNEXPECTED_ANSWER');
            }
            if (response_b64 === null){
                response_b64 = msg.response;
                return true;
            } else {
                response_b64 += msg.response;
                return true;
            }
        };
        /**
         * Returns the base64 encoded answer data with the content verified
         * against {@link permittedOperations}.
         */
        this.getMessage = function (){
            if (response_b64 === undefined){
                return gpgme_error('CONN_UNEXPECTED_ANSWER');
            }
            let _decodedResponse = JSON.parse(atob(response_b64));
            let _response = {};
            let messageKeys = Object.keys(_decodedResponse);
            let poa = permittedOperations[this.getOperation()].answer;
            if (messageKeys.length === 0){
                return gpgme_error('CONN_UNEXPECTED_ANSWER');
            }
            for (let i= 0; i < messageKeys.length; i++){
                let key = messageKeys[i];
                switch (key) {
                case 'type':
                    if (_decodedResponse.type === 'error'){
                        return (gpgme_error('GNUPG_ERROR',
                            decode(_decodedResponse.msg)));
                    } else if (poa.type.indexOf(_decodedResponse.type) < 0){
                        return gpgme_error('CONN_UNEXPECTED_ANSWER');
                    }
                    break;
                case 'base64':
                    break;
                case 'msg':
                    if (_decodedResponse.type === 'error'){
                        return (gpgme_error('GNUPG_ERROR',
                            _decodedResponse.msg));
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
                        && this.getExpect() !== 'base64'
                    ){
                        _response[key] = decodeURIComponent(
                            atob(_decodedResponse[key]).split('').map(
                                function(c) {
                                    return '%' +
                                ('00' + c.charCodeAt(0).toString(16)).slice(-2);
                                }).join(''));
                    } else {
                        _response[key] = decode(_decodedResponse[key]);
                    }
                    break;
                }
            }
            return _response;
        };
    }
}
