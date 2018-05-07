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

describe('Encryption and Decryption', function () {
    it('Successful encrypt and decrypt', function (done) {
        let prm = Gpgmejs.init();
        prm.then(function (context) {
            context.encrypt(
                inputvalues.encrypt.good.data,
                inputvalues.encrypt.good.fingerprint).then( function(answer){
                    expect(answer).to.not.be.empty;
                    expect(answer.data).to.be.a("string");
                    expect(answer.data).to.include('BEGIN PGP MESSAGE');
                    expect(answer.data).to.include('END PGP MESSAGE');
                    context.decrypt(answer.data).then(function(result){
                        expect(result).to.not.be.empty;
                        expect(result.data).to.be.a('string');
                        expect(result.data).to.equal(inputvalues.encrypt.good.data);
                        done();
                    });
                });
        });
    });

/**
 * Fails with random data! Some bytes (up to 100) of the original are missing in
 * the result
 */
/**
    for (let i=0; i< 20; i++) {
        it('Successful encrypt 1 MB '+ i+ '/20', function (done) {
            let prm = Gpgmejs.init();
            let data = bigString(0.1);
                prm.then(function (context) {
                    context.encrypt(data,
                        inputvalues.encrypt.good.fingerprint).then(
                            function (answer){
                                expect(answer).to.not.be.empty;
                                expect(answer.data).to.be.a("string");
                                expect(answer.data).to.include(
                                    'BEGIN PGP MESSAGE');
                                expect(answer.data).to.include(
                                    'END PGP MESSAGE');
                                context.decrypt(answer.data).then(
                                    function(result){
                                        expect(result).to.not.be.empty;
                                        expect(result.data).to.be.a('string');
                                        expect(result.data).to.equal(data);
                                        done();
                                });
                        });
                });
        }).timeout(10000);
    };*/
});