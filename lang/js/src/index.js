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
        connection.checkConnection(false).then(
            function(result){
                if (result === true) {
                    resolve(new GpgME(_conf));
                } else {
                    reject(gpgme_error('CONN_NO_CONNECT'));
                }
            }, function(error){
                reject(gpgme_error('CONN_NO_CONNECT'));
        });
    });
}

function parseconfiguration(rawconfig = {}){
    if ( typeof(rawconfig) !== 'object'){
        return gpgme_error('PARAM_WRONG');
    };
    let result_config = {};
    let conf_keys = Object.keys(rawconfig);

    for (let i=0; i < conf_keys.length; i++){

        if (availableConf.hasOwnProperty(conf_keys[i])){
            let value = rawconfig[conf_keys[i]];
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
    let default_keys = Object.keys(defaultConf);
    for (let j=0; j < default_keys.length; j++){
        if (!result_config.hasOwnProperty(default_keys[j])){
            result_config[default_keys[j]] = defaultConf[default_keys[j]];
        }
    }
    return result_config;
};

export default {
    init: init
}