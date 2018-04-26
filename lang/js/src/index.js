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
import { gpgme_error } from "./Errors";
import { GpgME_openpgpmode } from "./gpgmejs_openpgpjs";
import { Connection } from "./Connection";
import { defaultConf, availableConf } from "./Config";

/**
 * Initializes a nativeMessaging Connection and returns a GPGMEjs object
 * @param {Object} config Configuration. See Config.js for available parameters. Still TODO
 */
function init(config){
    let _conf = parseconfiguration(config);
    if (_conf instanceof Error){
        return Promise.reject(_conf);
    }
    return new Promise(function(resolve, reject){
        let connection = new Connection;
        // TODO: Delayed reaction is ugly. We need to listen to the port's
        // event listener in isConnected, but this takes some time (<5ms) to
        // disconnect if there is no successfull connection.
        let delayedreaction = function(){
            if (connection.isConnected === true){
                if (_conf.api_style && _conf.api_style === 'gpgme_openpgpjs'){
                    resolve(new GpgME_openpgpmode(connection, _conf));
                } else {
                    resolve(new GpgME(connection));
                }
            } else {
                reject(gpgme_error('CONN_NO_CONNECT'));
            }
        };
        setTimeout(delayedreaction, 5);
    });
}

function parseconfiguration(config){
    if (!config){
        return defaultConf;
    }
    if ( typeof(config) !== 'object'){
        return gpgme_error('PARAM_WRONG');
    };
    let result_config = defaultConf;
    let conf_keys = Object.keys(config);
    for (let i=0; i < conf_keys; i++){
        if (availableConf.hasOwnProperty(conf_keys[i])){
            let value = config[conf_keys[i]];
            if (availableConf[conf_keys[i]].indexOf(value) < 0){
                return gpgme_error('PARAM_WRONG');
            } else {
                result_config[conf_keys[i]] = value;
            }
        }
        else {
            return gpgme_error('PARAM_WRONG');
        }
    }
    return result_config;
};

export default {
    init: init
}