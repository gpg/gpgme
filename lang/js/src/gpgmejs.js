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

import {Connection} from "./Connection"
import {GPGME_Message} from './Message'
import {toKeyIdArray} from "./Helpers"

export class GpgME {
    /**
     * initial check if connection si successfull. Will throw ERR_NO_CONNECT or
     * ERR_NO_CONNECT_RLE (if chrome.runtime.lastError is available) if the
     * connection fails.
     * TODO The connection to the nativeMessaging host will, for now, be closed
     * after each interaction. Session management with gpg_agent is TBD.
     * TODO: add configuration
     */
    constructor(){
        let conn = new Connection();
        // this.keyring = new Keyring(); TBD
        // TODO config, e.g.
        this.configuration = {
            null_expire_is_never: true
        };
        conn.disconnect();
    }

    /**
     * @param {String|Uint8Array} data text/data to be encrypted as String/Uint8Array
     * @param  {GPGME_Key|String|Array<String>|Array<GPGME_Key>} publicKeys Keys used to encrypt the message
     * @param {Boolean} wildcard (optional) If true, recipient information will not be added to the message
     */
    encrypt (data, publicKeys, wildcard=false){

        let msg = new GPGME_Message;
        msg.operation = 'encrypt';

        // TODO temporary
        msg.setParameter('armor', true);
        msg.setParameter('always-trust', true);

        let pubkeys = toKeyIdArray(publicKeys);
        msg.setParameter('keys', pubkeys);

        putData(msg, data);
        if (wildcard === true){msg.setParameter('throw-keyids', true);
        };

        if (msg.isComplete === true) {
            let conn = new Connection();
            return (conn.post(msg.message));
        }
        else {
            return Promise.reject('NO_CONNECT');
            //TODO
        }
    }

    /**
    * @param  {String} data TODO Format: base64? String? Message with the encrypted data
    * @returns {Promise<Object>} decrypted message:
        data:   The decrypted data.  This may be base64 encoded.
        base64: Boolean indicating whether data is base64 encoded.
        mime:   A Boolean indicating whether the data is a MIME object.
        info:   An optional object with extra information.
    * @async
    */

    decrypt(data){

        if (data === undefined){
            throw('ERR_EMPTY_MSG');
        }
        let msg = new GPGME_Message;
        msg.operation = 'decrypt';
        putData(msg, data);
        // TODO: needs proper EOL to be decrypted.

        if (msg.isComplete === true){
            let conn = new Connection();
            return conn.post(msg.message);
        }
        else {
            return Promise.reject('NO_CONNECT');
            //TODO
        }
    }
}

/**
 * Sets the data of the message, converting Uint8Array to base64 and setting
 * the base64 flag
 * @param {GPGME_Message} message The message where this data will be set
 * @param {*} data The data to enter
 * @param {String} propertyname // TODO unchecked still
 */
function putData(message, data){
    if (!message || !message instanceof GPGME_Message ) {
        throw('NO_MESSAGE_OBJECT');
    }
    if (!data){
        //TODO Debug only! No data is legitimate
        console.log('Warning. no data in message');
        message.setParameter('data', '');
    } else if (data instanceof Uint8Array){
        let decoder = new TextDecoder('utf8');
        message.setParameter('base64', true);
        message.setParameter ('data', decoder.decode(data));
    } else if (typeof(data) === 'string') {
        message.setParameter('base64', false);
        message.setParameter('data', data);
    } else {
        throw('ERR_WRONG_TYPE');
    }
}