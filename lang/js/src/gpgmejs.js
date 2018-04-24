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
import {GPGMEJS_Error as Error, GPGMEJS_Error} from "./Errors"
import { GPGME_Keyring } from "./Keyring";

export class GpgME {
    /**
     * initializes GpgME by opening a nativeMessaging port
     * TODO: add configuration
     */
    constructor(connection){
        this.connection = connection;
    }

    set connection(connection){
        if (this._connection instanceof Connection){
            //TODO Warning: Connection already established
        }
        if (connection instanceof Connection){
            this._connection = connection;
        }
    }

    get connection(){
        if (this._connection instanceof Connection){
            if (this._connection.isConnected){
                return this._connection;
            }
            return undefined; //TODO: connection was lost!
        }
        return undefined; //TODO: no connection there
    }

    set Keyring(keyring){
        if (ring && ring instanceof GPGME_Keyring){
            this.Keyring = ring;
        }
    }

    get Keyring(){
    }

    /**
     * @param {String|Uint8Array} data text/data to be encrypted as String/Uint8Array
     * @param  {GPGME_Key|String|Array<String>|Array<GPGME_Key>} publicKeys Keys used to encrypt the message
     * @param {Boolean} wildcard (optional) If true, recipient information will not be added to the message
     */
    encrypt(data, publicKeys, wildcard=false){

        let msg = new GPGME_Message('encrypt');

        // TODO temporary
        msg.setParameter('armor', true);
        msg.setParameter('always-trust', true);

        let pubkeys = toKeyIdArray(publicKeys);
        msg.setParameter('keys', pubkeys);

        putData(msg, data);
        if (wildcard === true){msg.setParameter('throw-keyids', true);
        };

        return (this.connection.post(msg));
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
            return Promise.reject(new GPGMEJS_Error ('EMPTY_MSG'));
        }
        let msg = new GPGME_Message('decrypt');
        putData(msg, data);
        return this.connection.post(msg);

    }

    deleteKey(key, delete_secret = false, no_confirm = false){
        return Promise.reject(new GPGMEJS_Error ('NOT_YET_IMPLEMENTED'));
        let msg = new GPGME_Message('deletekey');
        let key_arr = toKeyIdArray(key);
        if (key_arr.length !== 1){
            throw('TODO');
            //should always be ONE key
        }
        msg.setParameter('key', key_arr[0]);
        if (delete_secret === true){
            msg.setParameter('allow_secret', true); //TBD
        }
        if (no_confirm === true){ //TODO: Do we want this hidden deep in the code?
            msg.setParameter('delete_force', true); //TBD
        }
        this.connection.post(msg).then(function(success){
            //TODO: it seems that there is always errors coming back:
        }, function(error){
            switch (error.msg){
            case 'ERR_NO_ERROR':
                return Promise.resolve('okay'); //TBD
            default:
                return Promise.reject(new GPGMEJS_Error);
                // INV_VALUE,
                // GPG_ERR_NO_PUBKEY,
                // GPG_ERR_AMBIGUOUS_NAME,
                // GPG_ERR_CONFLICT
            }
        });
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
        return new GPGMEJS_Error('WRONGPARAM');
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
    } else if ( typeof(data) === 'object' && data.hasOwnProperty(getText)){
        let txt = data.getText();
        if (txt instanceof Uint8Array){
            let decoder = new TextDecoder('utf8');
            message.setParameter('base64', true);
            message.setParameter ('data', decoder.decode(txt));
        }
    } else {
        return new GPGMEJS_Error('WRONGPARAM');
    }
}
