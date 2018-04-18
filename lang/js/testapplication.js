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
 */

function encryptbuttonclicked(event){
    let data = document.getElementById('cleartext').value;
    let keyId = document.getElementById('pubkey').value;
    let communication = new Gpgmejs;
    let enc = communication.encrypt(data, keyId).then(
        function(answer){
            console.log(answer);
            if (answer.data){
                console.log(answer.data);
                document.getElementById('answer').value = answer.data;
            }
        }, function(errormsg){
            alert('Error: '+ errormsg);
    });
};

function decryptbuttonclicked(event){
    let data = document.getElementById("ciphertext").value;
    let communication = new Gpgmejs;
    let enc = communication.decrypt(data).then(
        function(answer){
            console.log(answer);
            if (answer.data){
                document.getElementById('answer').value = answer.data;
            }
        }, function(errormsg){
            alert('Error: '+ errormsg);
    });
};

document.addEventListener('DOMContentLoaded', function() {
    document.getElementById("buttonencrypt").addEventListener("click",
            encryptbuttonclicked);
    document.getElementById("buttondecrypt").addEventListener("click",
        decryptbuttonclicked);
});
