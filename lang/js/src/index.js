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


import { GpgME } from './gpgmejs';
import { gpgme_error } from './Errors';
import { Connection } from './Connection';

/**
 * Initializes gpgme.js by testing the nativeMessaging connection once.
 * @returns {Promise<GpgME> | GPGME_Error}
 *
 * @async
 */
function init (){
    return new Promise(function (resolve, reject){
        const connection = new Connection;
        connection.checkConnection(false).then(
            function (result){
                if (result === true) {
                    resolve(new GpgME());
                } else {
                    reject(gpgme_error('CONN_NO_CONNECT'));
                }
            }, function (){ // unspecific connection error. Should not happen
                reject(gpgme_error('CONN_NO_CONNECT'));
            });
    });
}

const exportvalue = { init:init };
export default exportvalue;