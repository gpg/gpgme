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

/* global describe, it, before, expect, Gpgmejs */
/* global bigString, inputvalues, sabotageMsg*/

describe('Decryption', function () {
    let context = null;
    const good_fpr = inputvalues.encrypt.good.fingerprint;

    before(function (done){
        const prm = Gpgmejs.init();
        prm.then(function (gpgmejs){
            context = gpgmejs;
            done();
        });
    });

    it('Decryption of random string fails', function (done) {
        let data = bigString(20 * 1024);
        context.decrypt(data).then(
            function (){},
            function (error){
                expect(error).to.be.an('error');
                expect(error.code).to.equal('GNUPG_ERROR');
                done();
            });
    });

    it('Decryption of slightly corrupted message fails', function (done) {
        const data = bigString(10000);
        context.encrypt(data, good_fpr).then(function (enc){
            context.decrypt(sabotageMsg(enc.data)).then(
                function (){},
                function (error){
                    expect(error).to.be.an('error');
                    expect(error.code).to.equal('GNUPG_ERROR');
                    done();
                });
        });
    }).timeout(5000);


    it('decrypt/verify operations return proper information', function (done){
        const data = inputvalues.encryptSignedMessage;
        context.decrypt(data).then(function (result){
            expect(result).to.be.an('object');
            expect(result.signatures).to.be.an('object');
            expect(result.signatures.all_valid).to.be.true;
            expect(result.signatures.count).to.equal(1);
            expect(result.signatures.signatures.good).to.be.an('array');
            expect(
                result.signatures.signatures.good[0].fingerprint).to.equal(
                good_fpr);
            done();
        });
    });
});