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

/* global describe, it, expect, before, Gpgmejs */
/* global inputvalues*/

describe('Key information', function () {
    let context = null;
    before(function (done){
        const prm = Gpgmejs.init({ timeout: 2000 });
        prm.then(function (gpgmejs){
            context = gpgmejs;
            done();
        });
    });

    it('A fingerprint is consistently returned upper case hex', function (done){
        const mixedCase = inputvalues.encrypt.good.fingerprint_mixedcase;
        context.Keyring.getKeys({ pattern: mixedCase }).then(function (result){
            expect(result).to.be.an('array');
            expect(result.length).to.equal(1);
            expect(result[0].fingerprint).to.equal(mixedCase.toUpperCase());
            done();
        });
    });

    it('A userId keeps their encoding', function (done){
        context.Keyring.importKey(inputvalues.publicKeyNonAscii.key, true)
            .then(function (result){
                expect(result.Keys[0]).to.be.an('object');
                const user = result.Keys[0].key.get('userids')[0];
                expect(user.get('name')).to.equal(
                    inputvalues.publicKeyNonAscii.userid);
                result.Keys[0].key.delete().then(function (){
                    done();
                });
            });
    });
});
