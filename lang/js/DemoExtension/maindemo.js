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

/* global document, Gpgmejs */

document.addEventListener('DOMContentLoaded', function () {
    Gpgmejs.init().then(function (gpgmejs){
        document.getElementById('buttonencrypt').addEventListener('click',
            function (){
                let data = document.getElementById('inputtext').value;
                let keyId = document.getElementById('pubkey').value;
                gpgmejs.encrypt({ data: data, publicKeys: keyId, armor: true })
                    .then(function (answer){
                        if (answer.data){
                            document.getElementById(
                                'answer').value = answer.data;
                        }
                    }, function (errormsg){
                        alert( errormsg.message);
                    });
            });

        document.getElementById('buttondecrypt').addEventListener('click',
            function (){
                let data = document.getElementById('inputtext').value;
                gpgmejs.decrypt({ data: data }).then(
                    function (answer){
                        if (answer.data){
                            document.getElementById(
                                'answer').value = answer.data;
                        }
                    }, function (errormsg){
                        alert(errormsg.message);
                    });
            });

        document.getElementById('getdefaultkey').addEventListener('click',
            function (){
                gpgmejs.Keyring.getDefaultKey().then(function (answer){
                    document.getElementById('pubkey').value =
                        answer.fingerprint;
                }, function (errormsg){
                    alert(errormsg.message);
                });
            });

        document.getElementById('signtext').addEventListener('click',
            function (){
                let data = document.getElementById('inputtext').value;
                let keyId = document.getElementById('pubkey').value;
                gpgmejs.sign({ data: data, keys: keyId }).then(
                    function (answer){
                        if (answer.data){
                            document.getElementById(
                                'answer').value = answer.data;
                        }
                    }, function (errormsg){
                        alert( errormsg.message);
                    });
            });

        document.getElementById('verifytext').addEventListener('click',
            function (){
                let data = document.getElementById('inputtext').value;
                gpgmejs.verify({ data: data }).then(
                    function (answer){
                        let vals = '';
                        if (answer.all_valid === true){
                            vals = 'Success! ';
                        } else {
                            vals = 'Failure! ';
                        }
                        vals = vals + (answer.count - answer.failures) + 'of '
                            + answer.count + ' signature(s) were successfully '
                            + 'verified.\n\n' + answer.data;
                        document.getElementById('answer').value = vals;
                    }, function (errormsg){
                        alert( errormsg.message);
                    });
            });
        document.getElementById('searchkey').addEventListener('click',
            function (){
                let data = document.getElementById('inputtext').value;
                gpgmejs.Keyring.getKeys({
                    pattern: data,
                    prepare_sync: true,
                    search: true }
                ).then(function (keys){
                    if (keys.length === 1){
                        document.getElementById(
                            'pubkey').value = keys[0].fingerprint;
                    } else if (keys.length > 1) {
                        alert('The pattern was not unambiguous enough for a Key. '
                        + keys.length + ' Keys were found');
                    } else {
                        alert('No keys found');
                    }
                }, function (errormsg){
                    alert( errormsg.message);
                });
            });
    });
});
