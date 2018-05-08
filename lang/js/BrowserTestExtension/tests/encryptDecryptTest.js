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
                inputvalues.encrypt.good.fingerprint).then(function (answer) {
                    expect(answer).to.not.be.empty;
                    expect(answer.data).to.be.a("string");
                    expect(answer.data).to.include('BEGIN PGP MESSAGE');
                    expect(answer.data).to.include('END PGP MESSAGE');
                    context.decrypt(answer.data).then(function (result) {
                        expect(result).to.not.be.empty;
                        expect(result.data).to.be.a('string');
                        expect(result.data).to.equal(inputvalues.encrypt.good.data);
                        context.connection.disconnect();
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
    for (let j = 0; j < 10; j++){
    it('Successful encrypt and decrypt specific sets: ',
            function (done) {
                let prm = Gpgmejs.init();
                let data = bigBoringString(5); //see ./inputvalues.js
                expect(Object.prototype.toString.call(data)).to.equal("[object String]");
                prm.then(function (context) {
                    context.encrypt(data,
                        inputvalues.encrypt.good.fingerprint).then(
                        function (answer) {
                            expect(answer).to.not.be.empty;
                            expect(answer.data).to.be.a("string");
                            expect(answer.data).to.include(
                                'BEGIN PGP MESSAGE');
                            expect(answer.data).to.include(
                                'END PGP MESSAGE');
                            context.decrypt(answer.data).then(
                                function (result) {
                                    if (data.length !== result.data.length) {

                                        for (let k = 0; k < data.length; k++) {
                                            if (data[k] !== result.data[k]) {
                                                console.log(k);
                                                console.log(data[k - 2] + data[k - 1] + data[k] + data[k + 1]);
                                                console.log(result.data[k - 2] + result.data[k - 1] + result.data[k] + result.data[k + 1]);
                                                break;
                                            }
                                        }
                                    }
                                    expect(result).to.not.be.empty;
                                    expect(result.data).to.be.a('string');
                                    expect(result.data).to.equal(data);
                                    context.connection.disconnect();
                                    done();

                                });
                        });
                });
            }).timeout(5000);
        }


    it('Roundtrip does not destroy trailing whitespace',
        function (done) {
            let prm = Gpgmejs.init();
            prm.then(function (context) {
                let data = 'Keks. \rKeks \n Keks \r\n';
                context.encrypt(data,
                    inputvalues.encrypt.good.fingerprint).then(
                    function (answer) {
                        expect(answer).to.not.be.empty;
                        expect(answer.data).to.be.a("string");
                        expect(answer.data).to.include(
                            'BEGIN PGP MESSAGE');
                        expect(answer.data).to.include(
                            'END PGP MESSAGE');
                        context.decrypt(answer.data).then(
                            function (result) {
                                expect(result).to.not.be.empty;
                                expect(result.data).to.be.a('string');
                                expect(result.data).to.equal(data);
                                context.connection.disconnect();
                                done();

                            });
                    });
            });
        }).timeout(3000);

    it('Test with simple non-ascii input',
        function (done) {
            let prm = Gpgmejs.init();
            prm.then(function (context) {
                let data = '';
                for (let i=0; i < 1024 * 1024 * 0.1; i++){
                    data += inputvalues.encrypt.good.data_nonascii;
                }
                context.encrypt(data,
                    inputvalues.encrypt.good.fingerprint).then(
                    function (answer) {
                        expect(answer).to.not.be.empty;
                        expect(answer.data).to.be.a("string");
                        expect(answer.data).to.include(
                            'BEGIN PGP MESSAGE');
                        expect(answer.data).to.include(
                            'END PGP MESSAGE');
                        console.log(answer);
                        context.decrypt(answer.data).then(
                            function (result) {
                                expect(result).to.not.be.empty;
                                expect(result.data).to.be.a('string');
                                if (data.length !== result.data.length) {

                                    for (let k = 0; k < data.length; k++) {
                                        if (data[k] !== result.data[k]) {
                                            console.log(k);
                                            console.log(data[k - 2] + data[k - 1] + data[k] + data[k + 1]);
                                            console.log(result.data[k - 2] + result.data[k - 1] + result.data[k] + result.data[k + 1]);
                                            break;
                                        }
                                    }
                                }
                                console.log(data.length - result.data.length);
                                expect(result.data).to.equal(data);
                                context.connection.disconnect();
                                done();

                            });
                    });
            });
        }).timeout(3000);
*/
/**
    for (let i=0; i< 100; i++) {
        it('Successful encrypt random data '+ (i+1) + '/100', function (done) {
            let prm = Gpgmejs.init();
            let data = bigString(0.2); // << set source data here
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
                                        context.connection.disconnect();
                                        done();
                                });
                        });
                });
        }).timeout(5000);
    };
*/

/** still fails
    it('Successful encrypt 0.8 MB Uint8Array', function (done) {
        let prm = Gpgmejs.init();
        let data = bigUint8(0.8);
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
    }).timeout(5000);
*/

    it('Decrypt simple non-ascii',
        function (done) {
            let prm = Gpgmejs.init();
            prm.then(function (context) {
                data = encryptedData;
                context.decrypt(data).then(
                    function (result) {
                        expect(result).to.not.be.empty;
                        expect(result.data).to.be.a('string');
                        expect(result.data).to.equal(inputvalues.encrypt.good.data_nonascii);
                        context.encrypt(inputvalues.encrypt.good.data_nonascii, inputvalues.encrypt.good.fingerprint).then(
                            function(result){
                                context.decrypt(result.data).then(function(answer){
                                    expect(answer.data).to.equal(inputvalues.encrypt.good.data_nonascii);
                                    context.connection.disconnect();
                                    done();
                                });
                            });
                        });

            });
    }).timeout(8000);

});