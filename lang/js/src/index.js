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

import { GpgME } from "./gpgmejs";
import { GPGMEJS_Error } from "./Errors";
import { GpgME_openpgpmode } from "./gpgmejs_openpgpjs";
import { Connection } from "./Connection";

/**
 * Initializes a nativeMessaging Connection and returns a GPGMEjs object
 * @param {*} conf Configuration. TBD
 */
function init( config = {
    api_style: 'gpgme', //  | gpgme_openpgpjs
    null_expire_is_never: true // Boolean
    }){
        return new Promise(function(resolve, reject){
            let connection = new Connection;
            // TODO: Delayed reaction is ugly. We need to listen to the port's
            // event listener in isConnected, but this takes some time (<5ms) to
            // disconnect if there is no successfull connection.
            let delayedreaction = function(){
                if (connection.isConnected === true){
                    let gpgme = null;
                    if (config.api_style && config.api_style === 'gpgme_openpgpjs'){
                        resolve(
                            new GpgME_openpgpmode(connection));
                    } else {
                        resolve(new GpgME(connection));
                    }
                } else {
                    reject(GPGMEJS_Error('CONN_NO_CONNECT'));
                }
            };
            setTimeout(delayedreaction, 5);
    });
};

export default {
    init: init
}