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

/* global chrome */

import { permittedOperations } from './permittedOperations';
import { gpgme_error } from './Errors';
import { GPGME_Message, createMessage } from './Message';
import { decode, atobArray, Utf8ArrayToStr } from './Helpers';

/**
 * A Connection handles the nativeMessaging interaction via a port. As the
 * protocol only allows up to 1MB of message sent from the nativeApp to the
 * browser, the connection will stay open until all parts of a communication
 * are finished. For a new request, a new port will open, to avoid mixing
 * contexts.
 * @class
 * @private
 */
export class Connection{

    constructor (){
        this._connectionError = null;
        this._connection = chrome.runtime.connectNative('gpgmejson');
        this._connection.onDisconnect.addListener(() => {
            if (chrome.runtime.lastError) {
                this._connectionError = chrome.runtime.lastError.message;
            } else {
                this._connectionError = 'Disconnected without error message';
            }
        });
    }

    /**
     * Immediately closes an open port.
     */
    disconnect () {
        if (this._connection){
            this._connection.disconnect();
            this._connection = null;
            this._connectionError = 'Disconnect requested by gpgmejs';
        }
    }

    /**
     * Checks if the connection terminated with an error state
     */
    get isDisconnected (){
        return this._connectionError !== null;
    }

    /**
    * @typedef {Object} backEndDetails
    * @property {String} gpgme Version number of gpgme
    * @property {Array<Object>} info Further information about the backend
    * and the used applications (Example:
    * <pre>
    * {
    *          "protocol":     "OpenPGP",
    *          "fname":        "/usr/bin/gpg",
    *          "version":      "2.2.6",
    *          "req_version":  "1.4.0",
    *          "homedir":      "default"
    * }
    * </pre>
    */

    /**
     * Retrieves the information about the backend.
     * @param {Boolean} details (optional) If set to false, the promise will
     *  just return if a connection was successful.
     * @param {Number} timeout (optional)
     * @returns {Promise<backEndDetails>|Promise<Boolean>} Details from the
     * backend
     * @async
     */
    checkConnection (details = true, timeout = 1000){
        if (typeof timeout !== 'number' && timeout <= 0) {
            timeout = 1000;
        }
        const msg = createMessage('version');
        const prm = Promise.race([
            this.post(msg),
            new Promise(function (resolve, reject){
                setTimeout(function (){
                    reject(gpgme_error('CONN_TIMEOUT'));
                }, timeout);
            })
        ]);
        return new Promise( function (resolve, reject) {
            prm.then(function (success){
                if (details === true ) {
                    resolve(success);
                } else {
                    resolve(true);
                }
            }, function (error) {
                if (details === true ) {
                    reject(error);
                } else {
                    resolve(false);
                }
            });
        });
    }

    /**
     * Sends a {@link GPGME_Message} via the nativeMessaging port. It
     * resolves with the completed answer after all parts have been
     * received and reassembled, or rejects with an {@link GPGME_Error}.
     *
     * @param {GPGME_Message} message
     * @returns {Promise<*>} The collected answer, depending on the messages'
     * operation
     * @private
     * @async
     */
    post (message){
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
        const me = this;
        const nativeCommunication = new Promise(function (resolve, reject){
            let answer = new Answer(message);
            let listener = function (msg) {
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
            me._connection.onMessage.addListener(listener);
            me._connection.postMessage(message.message);

            // check for browser messaging errors after a while
            // (browsers' extension permission checks take some time)
            setTimeout( () => {
                if (me.isDisconnected) {
                    if ( me.isNativeHostUnknown === true) {
                        return reject(gpgme_error('CONN_NO_CONFIG'));
                    } else {
                        return reject(gpgme_error(
                            'CONN_NO_CONNECT', me._connectionError));
                    }
                }
            }, 25);

        });
        if (permittedOperations[message.operation].pinentry === true) {
            return nativeCommunication;
        } else {
            return Promise.race([
                nativeCommunication,
                new Promise(function (resolve, reject){
                    setTimeout(function (){
                        me.disconnect();
                        reject(gpgme_error('CONN_TIMEOUT'));
                    }, 5000);
                })
            ]);
        }
    }
}


/**
 * A class for answer objects, checking and processing the return messages of
 * the nativeMessaging communication.
 * @private
 */
class Answer{

    /**
     * @param {GPGME_Message} message
     */
    constructor (message){
        this._operation = message.operation;
        this._expected = message.expected;
        this._response_b64 = null;
    }

    get operation (){
        return this._operation;
    }

    get expected (){
        return this._expected;
    }

    /**
     * Checks if an error matching browsers 'host not known' messages occurred
     */
    get isNativeHostUnknown () {
        return this._connectionError === 'Specified native messaging host not found.';
    }

    /**
     * Adds incoming base64 encoded data to the existing response
     * @param {*} msg base64 encoded data.
     * @returns {Boolean}
     *
     * @private
     */
    collect (msg){
        if (typeof (msg) !== 'object' || !msg.hasOwnProperty('response')) {
            return gpgme_error('CONN_UNEXPECTED_ANSWER');
        }
        if (!this._response_b64){
            this._response_b64 = msg.response;
            return true;
        } else {
            this._response_b64 += msg.response;
            return true;
        }
    }
    /**
     * Decodes and verifies the base64 encoded answer data. Verified against
     * {@link permittedOperations}.
     * @returns {Object} The readable gpnupg answer
     */
    getMessage (){
        if (this._response_b64 === null){
            return gpgme_error('CONN_UNEXPECTED_ANSWER');
        }
        let _decodedResponse = JSON.parse(atob(this._response_b64));
        let _response = {
            format: 'ascii'
        };
        let messageKeys = Object.keys(_decodedResponse);
        let poa = permittedOperations[this.operation].answer;
        if (messageKeys.length === 0){
            return gpgme_error('CONN_UNEXPECTED_ANSWER');
        }
        for (let i= 0; i < messageKeys.length; i++){
            let key = messageKeys[i];
            switch (key) {
            case 'type': {
                if (_decodedResponse.type === 'error'){
                    return (gpgme_error('GNUPG_ERROR',
                        decode(_decodedResponse.msg)));
                } else if (poa.type.indexOf(_decodedResponse.type) < 0){
                    return gpgme_error('CONN_UNEXPECTED_ANSWER');
                }
                break;
            }
            case 'base64': {
                break;
            }
            case 'msg': {
                if (_decodedResponse.type === 'error'){
                    return (gpgme_error('GNUPG_ERROR', _decodedResponse.msg));
                }
                break;
            }
            default: {
                let answerType = null;
                if (poa.payload && poa.payload.hasOwnProperty(key)){
                    answerType = 'p';
                } else if (poa.info && poa.info.hasOwnProperty(key)){
                    answerType = 'i';
                }
                if (answerType !== 'p' && answerType !== 'i'){
                    return gpgme_error('CONN_UNEXPECTED_ANSWER');
                }

                if (answerType === 'i') {
                    if ( typeof (_decodedResponse[key]) !== poa.info[key] ){
                        return gpgme_error('CONN_UNEXPECTED_ANSWER');
                    }
                    _response[key] = decode(_decodedResponse[key]);

                } else if (answerType === 'p') {
                    if (_decodedResponse.base64 === true
                        && poa.payload[key] === 'string'
                    ) {
                        if (this.expected === 'uint8'){
                            _response[key] = atobArray(_decodedResponse[key]);
                            _response.format = 'uint8';

                        } else if (this.expected === 'base64'){
                            _response[key] = _decodedResponse[key];
                            _response.format = 'base64';

                        } else { // no 'expected'
                            _response[key] = Utf8ArrayToStr(
                                atobArray(_decodedResponse[key]));
                            _response.format = 'string';
                        }
                    } else if (poa.payload[key] === 'string') {
                        _response[key] = _decodedResponse[key];
                    } else {
                        // fallthrough, should not be reached
                        // (payload is always string)
                        return gpgme_error('CONN_UNEXPECTED_ANSWER');
                    }
                }
                break;
            } }
        }
        return _response;
    }
}
