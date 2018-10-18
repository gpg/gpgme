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
/* global inputvalues, encryptedData, bigString, bigBoringString */

describe('Encryption and Decryption', function (){
    let context = null;
    let good_fpr = inputvalues.encrypt.good.fingerprint;

    before(function (done){
        const prm = Gpgmejs.init({ timeout: 2000 });
        prm.then(function (gpgmejs){
            context = gpgmejs;
            done();
        });
    });

    it('Successful encrypt and decrypt simple string', function (done) {
        let data = inputvalues.encrypt.good.data;
        context.encrypt({ data: data, publicKeys: good_fpr }).then(
            function (answer) {
                expect(answer).to.not.be.empty;
                expect(answer.data).to.be.a('string');
                expect(answer.data).to.include('BEGIN PGP MESSAGE');
                expect(answer.data).to.include('END PGP MESSAGE');
                context.decrypt({ data: answer.data }).then(function (result) {
                    expect(result).to.not.be.empty;
                    expect(result.data).to.be.a('string');
                    expect(result.data).to.equal(
                        inputvalues.encrypt.good.data);
                    done();
                });
            });
    });

    it('Decrypt simple non-ascii', function (done) {
        let data = encryptedData;
        context.decrypt({ data: data }).then(function (result) {
            expect(result).to.not.be.empty;
            expect(result.data).to.be.a('string');
            expect(result.data).to.equal(
                '¡Äußerste µ€ før ñoquis@hóme! Добрый день\n');
            done();
        });
    }).timeout(3000);

    it('Trailing whitespace and different line endings', function (done) {
        const data = 'Keks. \rKeks \n Keks \r\n';
        context.encrypt({ data: data, publicKeys: good_fpr }).then(
            function (answer) {
                expect(answer).to.not.be.empty;
                expect(answer.data).to.be.a('string');
                expect(answer.data).to.include('BEGIN PGP MESSAGE');
                expect(answer.data).to.include('END PGP MESSAGE');

                context.decrypt({ data: answer.data }).then(function (result) {
                    expect(result).to.not.be.empty;
                    expect(result.data).to.be.a('string');
                    expect(result.data).to.equal(data);
                    done();
                });
            });
    }).timeout(5000);

    it('Random data, as string', function (done) {
        let data = bigString(1000);
        context.encrypt({ data:data, publicKeys: good_fpr }).then(
            function (answer) {
                expect(answer).to.not.be.empty;
                expect(answer.data).to.be.a('string');
                expect(answer.data).to.include(
                    'BEGIN PGP MESSAGE');
                expect(answer.data).to.include(
                    'END PGP MESSAGE');
                context.decrypt({ data: answer.data }).then(function (result) {
                    expect(result).to.not.be.empty;
                    expect(result.data).to.be.a('string');
                    expect(result.data).to.equal(data);
                    done();
                });
            });
    }).timeout(3000);

    it('Data, input as base64', function (done) {
        let data = inputvalues.encrypt.good.data;
        let b64data = btoa(data);
        context.encrypt({ data: b64data, publicKeys: good_fpr, base64: true })
            .then(function (answer) {
                expect(answer).to.not.be.empty;
                expect(answer.data).to.be.a('string');
                expect(answer.data).to.include(
                    'BEGIN PGP MESSAGE');
                expect(answer.data).to.include(
                    'END PGP MESSAGE');
                context.decrypt({ data: answer.data }).then(function (result) {
                    expect(result).to.not.be.empty;
                    expect(result.data).to.be.a('string');
                    expect(result.data).to.equal(data);
                    done();
                });
            });
    }).timeout(3000);

    it('Random data, input as base64', function (done) {
        let data = bigBoringString(0.001);
        let b64data = btoa(data);
        context.encrypt(
            { data: b64data, publicKeys: good_fpr, base64: true })
            .then(function (answer) {
                expect(answer).to.not.be.empty;
                expect(answer.data).to.be.a('string');
                expect(answer.data).to.include(
                    'BEGIN PGP MESSAGE');
                expect(answer.data).to.include(
                    'END PGP MESSAGE');
                context.decrypt({ data:answer.data }).then(
                    function (result) {
                        expect(result).to.not.be.empty;
                        expect(result.data).to.be.a('string');
                        expect(result.data).to.equal(data);
                        done();
                    });
            });
    }).timeout(3000);

    it('Random data, original data is and should stay base64 encoded',
        function (done) {
            let data = bigBoringString(0.001);
            let b64data = btoa(data);
            context.encrypt(
                { data: b64data, publicKeys: good_fpr })
                .then(function (answer) {
                    expect(answer).to.not.be.empty;
                    expect(answer.data).to.be.a('string');
                    expect(answer.data).to.include(
                        'BEGIN PGP MESSAGE');
                    expect(answer.data).to.include(
                        'END PGP MESSAGE');
                    context.decrypt({
                        data:answer.data, expect: 'base64' })
                        .then(function (result) {
                            expect(result).to.not.be.empty;
                            expect(result.data).to.be.a('string');
                            expect(result.data).to.equal(b64data);
                            done();
                        });
                });
    }).timeout(3000);

    for (let j = 0; j < inputvalues.encrypt.good.data_nonascii_32.length; j++){
        it('Roundtrip with >1MB non-ascii input meeting default chunksize (' +
            (j + 1) + '/'
            + inputvalues.encrypt.good.data_nonascii_32.length + ')',
        function (done) {
            let input = inputvalues.encrypt.good.data_nonascii_32[j];
            expect(input).to.have.length(32);
            let data = '';
            for (let i=0; i < 34 * 1024; i++){
                data += input;
            }
            context.encrypt({ data: data, publicKeys: good_fpr })
                .then(function (answer) {
                    expect(answer).to.not.be.empty;
                    expect(answer.data).to.be.a('string');
                    expect(answer.data).to.include(
                        'BEGIN PGP MESSAGE');
                    expect(answer.data).to.include(
                        'END PGP MESSAGE');
                    context.decrypt({ data: answer.data })
                        .then(function (result) {
                            expect(result).to.not.be.empty;
                            expect(result.data).to.be.a('string');
                            expect(result.data).to.equal(data);
                            done();
                        });
                });
        }).timeout(5000);
    }
});
