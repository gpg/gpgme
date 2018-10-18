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

/* global describe, it, expect, before, bigString, inputvalues, Gpgmejs */



describe('Verifying data', function () {
    let context = null;
    before(function (done){
        const prm = Gpgmejs.init({ timeout: 2000 });
        prm.then(function (gpgmejs){
            context = gpgmejs;
            done();
        });
    });
    it('Successful verify message', function (done) {
        const message = inputvalues.signedMessage.good;
        context.verify({ data: message }).then(function (result){
            expect(result.data).to.be.a('string');
            expect(result.signatures.all_valid).to.be.true;
            expect(result.signatures.count).to.equal(1);
            expect(result.signatures.signatures.good).to.be.an('array');
            expect(result.signatures.signatures.good.length).to.equal(1);
            expect(result.signatures.signatures.good[0].fingerprint).to.be.a('string');
            expect(result.signatures.signatures.good[0].valid).to.be.true;
            done();
        });
    });

    it('Successfully recognize changed cleartext', function (done) {
        const message = inputvalues.signedMessage.bad;
        context.verify({ data: message }).then(function (result){
            expect(result.data).to.be.a('string');
            expect(result.signatures.all_valid).to.be.false;
            expect(result.signatures.count).to.equal(1);
            expect(result.signatures.signatures.bad).to.be.an('array');
            expect(result.signatures.signatures.bad.length).to.equal(1);
            expect(result.signatures.signatures.bad[0].fingerprint)
                .to.be.a('string');
            expect(result.signatures.signatures.bad[0].valid)
                .to.be.false;
            done();
        });
    });

    it('Encrypt-Sign-Verify random message', function (done) {
        const message = bigString(2000);
        let fpr = inputvalues.encrypt.good.fingerprint;
        context.encrypt({ data: message, publicKeys: fpr })
            .then(function (message_enc){
                context.sign({ data: message_enc.data, keys: fpr })
                    .then(function (message_encsign){
                        context.verify({ data: message_encsign.data })
                            .then(function (result){
                                expect(result.data).to.equal(message_enc.data);
                                expect(result.data).to.be.a('string');
                                expect(result.signatures.all_valid).to.be.true;
                                expect(result.signatures.count).to.equal(1);
                                const arr = result.signatures.signatures.good;
                                expect(arr).to.be.an('array');
                                expect(arr.length).to.equal(1);
                                expect(arr[0].fingerprint).to.equal(fpr);
                                expect(arr[0].valid).to.be.true;
                                done();
                            });
                    });
            });
    });
});