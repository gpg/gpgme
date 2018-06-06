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

/* global describe, it, expect, Gpgmejs */
/* global inputvalues, fixedLengthString */

describe('Encryption', function () {
    it('Successful encrypt', function (done) {
        let prm = Gpgmejs.init();
        prm.then(function (context) {
            context.encrypt(
                inputvalues.encrypt.good.data,
                inputvalues.encrypt.good.fingerprint).then(function (answer) {
                expect(answer).to.not.be.empty;
                expect(answer.data).to.be.a('string');
                expect(answer.data).to.include('BEGIN PGP MESSAGE');
                expect(answer.data).to.include('END PGP MESSAGE');
                done();
            });
        });
    });

    it('Successful encrypt 5 MB', function (done) {
        let prm = Gpgmejs.init();
        let data = fixedLengthString(5);
        prm.then(function (context) {
            context.encrypt(
                data,
                inputvalues.encrypt.good.fingerprint).then(function (answer) {
                expect(answer).to.not.be.empty;
                expect(answer.data).to.be.a('string');
                expect(answer.data).to.include('BEGIN PGP MESSAGE');
                expect(answer.data).to.include('END PGP MESSAGE');
                done();
            });
        });
    }).timeout(10000);

    it('Successful encrypt 20 MB', function (done) {
        let prm = Gpgmejs.init();
        let data = fixedLengthString(20);
        prm.then(function (context) {
            context.encrypt(
                data,
                inputvalues.encrypt.good.fingerprint).then(function (answer) {
                expect(answer).to.not.be.empty;
                expect(answer.data).to.be.a('string');
                expect(answer.data).to.include('BEGIN PGP MESSAGE');
                expect(answer.data).to.include('END PGP MESSAGE');
                done();
            });
        });
    }).timeout(20000);

    it('Successful encrypt 50 MB', function (done) {
        let prm = Gpgmejs.init();
        let data = fixedLengthString(50);
        prm.then(function (context) {
            context.encrypt(
                data,
                inputvalues.encrypt.good.fingerprint).then(function (answer) {
                expect(answer).to.not.be.empty;
                expect(answer.data).to.be.a('string');
                expect(answer.data).to.include('BEGIN PGP MESSAGE');
                expect(answer.data).to.include('END PGP MESSAGE');
                done();
            });
        });
    }).timeout(20000);

    it('Sending encryption without keys fails', function (done) {
        let prm = Gpgmejs.init();
        prm.then(function (context) {
            context.encrypt(
                inputvalues.encrypt.good.data,
                null).then(function (answer) {
                expect(answer).to.be.undefined;
            }, function(error){
                expect(error).to.be.an('Error');
                expect(error.code).to.equal('MSG_INCOMPLETE');
                done();
            });
        });
    });

    it('Sending encryption without data fails', function (done) {
        let prm = Gpgmejs.init();
        prm.then(function (context) {
            context.encrypt(
                null, inputvalues.encrypt.good.keyid).then(function (answer) {
                expect(answer).to.be.undefined;
            }, function (error) {
                expect(error).to.be.an.instanceof(Error);
                expect(error.code).to.equal('MSG_INCOMPLETE');
                done();
            });
        });
    });

    it('Sending encryption with non existing keys fails', function (done) {
        let prm = Gpgmejs.init();
        prm.then(function (context) {
            context.encrypt(
                inputvalues.encrypt.good.data,
                inputvalues.encrypt.bad.fingerprint).then(function (answer) {
                expect(answer).to.be.undefined;
            }, function(error){
                expect(error).to.be.an('Error');
                expect(error.code).to.not.be.undefined;
                expect(error.code).to.equal('GNUPG_ERROR');
                done();
            });
        });
    }).timeout(5000);

    it('Overly large message ( > 65MB) is rejected', function (done) {
        let prm = Gpgmejs.init();
        prm.then(function (context) {
            context.encrypt(
                fixedLengthString(65),
                inputvalues.encrypt.good.fingerprint).then(function (answer) {
                expect(answer).to.be.undefined;
            }, function(error){
                expect(error).to.be.an.instanceof(Error);
                // expect(error.code).to.equal('GNUPG_ERROR');
                // TODO: there is a 64 MB hard limit at least in chrome at:
                // chromium//extensions/renderer/messaging_util.cc:
                // kMaxMessageLength
                done();
            });
        });
    }).timeout(8000);

    // TODO check different valid parameter
});
