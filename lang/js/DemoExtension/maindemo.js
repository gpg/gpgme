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

/* global document, Gpgmejs */

document.addEventListener('DOMContentLoaded', function() {
    Gpgmejs.init().then(function(gpgmejs){
        document.getElementById('buttonencrypt').addEventListener('click',
            function(){
                let data = document.getElementById('cleartext').value;
                let keyId = document.getElementById('pubkey').value;
                gpgmejs.encrypt(data, keyId).then(
                    function(answer){
                        if (answer.data){
                            document.getElementById(
                                'answer').value = answer.data;
                        }
                    }, function(errormsg){
                        alert( errormsg.message);
                    });
            });

        document.getElementById('buttondecrypt').addEventListener('click',
            function(){
                let data = document.getElementById('ciphertext').value;
                gpgmejs.decrypt(data).then(
                    function(answer){
                        if (answer.data){
                            document.getElementById(
                                'answer').value = answer.data;
                        }
                    }, function(errormsg){
                        alert(errormsg.message);
                    });
            });

        document.getElementById('getdefaultkey').addEventListener('click',
            function(){
                gpgmejs.Keyring.getDefaultKey().then(function(answer){
                    document.getElementById('defaultkey').textContent =
                        answer.fingerprint;
                }, function(errormsg){
                    alert(errormsg.message);
                });
            });
    });
});
