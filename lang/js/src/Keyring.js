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

import {createMessage} from './Message'
import {GPGME_Key} from './Key'
import { isFingerprint, isLongId } from './Helpers';
import { gpgme_error } from './Errors';
import { Connection } from './Connection';

export class GPGME_Keyring {
    constructor(connection){
        this.connection = connection;
    }

    set connection(connection){
        if (!this._connection && connection instanceof Connection){
            this._connection = connection;
        }
    }
    get connection(){
        if (this._connection instanceof Connection){
            if (this._connection.isConnected){
                return this._connection;
            }
            return gpgme_error('CONN_DISCONNECTED');
        }
        return gpgme_error('CONN_NO_CONNECT');
    }

    /**
     * @param {String} (optional) pattern A pattern to search for, in userIds or KeyIds
     * @param {Boolean} (optional) Include listing of secret keys
     * @returns {Promise.<Array<GPGME_Key>>}
     *
     */
    getKeys(pattern, include_secret){
        let msg = createMessage('listkeys');
        if (msg instanceof Error){
            return Promise.reject(msg);
        }
        if (pattern && typeof(pattern) === 'string'){
            msg.setParameter('pattern', pattern);
        }
        if (include_secret){
            msg.setParameter('with-secret', true);
        }

        this.connection.post(msg).then(function(result){
            let fpr_list = [];
            let resultset = [];
            if (!Array.isArray(result.keys)){
            //TODO check assumption keys = Array<String fingerprints>
                fpr_list = [result.keys];
            } else {
                fpr_list = result.keys;
            }
            for (let i=0; i < fpr_list.length; i++){
                let newKey = new GPGME_Key(fpr_list[i]);
                if (newKey instanceof GPGME_Key){
                    resultset.push(newKey);
                }
            }
            return Promise.resolve(resultset);
        }, function(error){
            //TODO error handling
        });
    }

    /**
     * @param {Object} flags subset filter expecting at least one of the
     * filters described below. True will filter on the condition, False will
     * reverse the filter, if not present or undefined, the filter will not be
     * considered. Please note that some combination may not make sense
     * @param {Boolean} flags.secret Only Keys containing a secret part.
     * @param {Boolean} flags.revoked revoked Keys only
     * @param {Boolean} flags.expired Expired Keys only
     * @param {String} (optional) pattern A pattern to search for, in userIds or KeyIds
     * @returns {Promise Array<GPGME_Key>}
     *
     */
    getSubset(flags, pattern){
        if (flags === undefined) {
            throw('ERR_WRONG_PARAM');
        };
        let secretflag = false;
        if (flags.hasOwnProperty(secret) && flags.secret){
            secretflag = true;
        }
        this.getKeys(pattern, secretflag).then(function(queryset){
            let resultset = [];
            for (let i=0; i < queryset.length; i++ ){
                let conditions = [];
                let anticonditions = [];
                if (secretflag === true){
                    conditions.push('hasSecret');
                } else if (secretflag === false){
                    anticonditions.push('hasSecret');
                }
                /**
                if (flags.defaultKey === true){
                    conditions.push('isDefault');
                } else if (flags.defaultKey === false){
                    anticonditions.push('isDefault');
                }
                */
                /**
                 * if (flags.valid === true){
                    anticonditions.push('isInvalid');
                } else if (flags.valid === false){
                    conditions.push('isInvalid');
                }
                */
                if (flags.revoked === true){
                    conditions.push('isRevoked');
                } else if (flags.revoked === false){
                    anticonditions.push('isRevoked');
                }
                if (flags.expired === true){
                    conditions.push('isExpired');
                } else if (flags.expired === false){
                    anticonditions.push('isExpired');
                }
                let decision = undefined;
                for (let con = 0; con < conditions.length; con ++){
                    if (queryset[i][conditions[con]] !== true){
                        decision = false;
                    }
                }
                for (let acon = 0; acon < anticonditions.length; acon ++){
                    if (queryset[i][anticonditions[acon]] === true){
                        decision = false;
                    }
                }
                if (decision !== false){
                    resultset.push(queryset[i]);
                }
            }
            return Promise.resolve(resultset);
        }, function(error){
            //TODO error handling
        });
    }

};
