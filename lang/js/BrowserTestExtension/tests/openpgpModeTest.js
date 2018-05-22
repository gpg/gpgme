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

describe('Encrypting-Decrypting in openpgp mode, using a Message object', function () {
    it('Simple Encrypt-Decrypt', function (done) {
        let prm = Gpgmejs.init({api_style: 'gpgme_openpgpjs'});
        prm.then(function (context) {
            context.encrypt({
                data: openpgp.message.fromText(inputvalues.encrypt.good.data),
                publicKeys: inputvalues.encrypt.good.fingerprint}
            ).then(function (answer) {
                    expect(answer).to.not.be.empty;
                    expect(answer).to.be.an("object");
                    expect(answer.data).to.include('BEGIN PGP MESSAGE');
                    expect(answer.data).to.include('END PGP MESSAGE');
                    let msg = openpgp.message.fromText(answer.data);
                    context.decrypt({message:msg}).then(function (result) {
                        expect(result).to.not.be.empty;
                        expect(result.data).to.be.a('string');
                        expect(result.data).to.equal(inputvalues.encrypt.good.data);
                        context._GpgME.connection.disconnect();
                        done();
                    });
                });
        });
    });
    it('Keys as Fingerprints', function(done){
        let prm = Gpgmejs.init({api_style: 'gpgme_openpgpjs'});
            let input = inputvalues.encrypt.good.data_nonascii;
            prm.then(function (context) {
                context.encrypt({
                    data: input,
                    publicKeys: inputvalues.encrypt.good.fingerprint}
                ).then(function (answer) {
                    expect(answer).to.not.be.empty;
                    expect(answer.data).to.be.a("string");
                    expect(answer.data).to.include('BEGIN PGP MESSAGE');
                    expect(answer.data).to.include('END PGP MESSAGE');
                    context.decrypt({message:answer.data}).then(function (result) {
                        expect(result).to.not.be.empty;
                        expect(result.data).to.be.a('string');
                        expect(result.data).to.equal(input);
                        context._GpgME.connection.disconnect();
                        done();
                    });
                });
            });
    });
    it('Keys as openpgp Keys', function(){
        let prm = Gpgmejs.init({api_style: 'gpgme_openpgpjs'});
        let data = inputvalues.encrypt.good.data_nonascii;
        let key = openpgp.key.readArmored(openpgpInputs.pubKeyArmored);
        expect(key).to.be.an('object');
        prm.then(function (context) {
            context.encrypt({
                data: data,
                publicKeys: [key]}
            ).then( function (answer) {
                expect(answer).to.not.be.empty;
                expect(answer.data).to.be.a("string");
                expect(answer.data).to.include('BEGIN PGP MESSAGE');
                expect(answer.data).to.include('END PGP MESSAGE');
                context.decrypt({message:answer.data}).then( function (result){
                    expect(result).to.not.be.empty;
                    expect(result.data).to.be.a('string');
                    expect(result.data).to.equal(data);
                    context._GpgME.connection.disconnect();
                    done();
                });
            });
        });
    });
    it('Trying to send non-implemented parameters: passwords', function(done){
        let prm = Gpgmejs.init({api_style: 'gpgme_openpgpjs'});
        let data = 'Hello World';
        let key = inputvalues.encrypt.good.fingerprint;
        prm.then(function (context) {
            context.encrypt({
                data: data,
                publicKeys: [key],
                passwords: 'My secret password'}
            ).then( function(){},
            function(error){
                expect(error).to.be.an.instanceof(Error);
                expect(error.code).equal('NOT_IMPLEMENTED');
                done();
            });
        });
    });
    it('Trying to send non-implemented parameters: signature', function(done){
        let prm = Gpgmejs.init({api_style: 'gpgme_openpgpjs'});
        let data = 'Hello World';
        let key = inputvalues.encrypt.good.fingerprint;
        prm.then(function (context) {
            context.encrypt({
                data: data,
                publicKeys: [key],
                signature: {any: 'value'}
            }).then(
                function(){},
                function(error){
                    expect(error).to.be.an.instanceof(Error);
                    expect(error.code).equal('NOT_IMPLEMENTED');
                    done();
                });
        });
    });
});

describe('Keyring in openpgp mode', function(){
    it('Check Existence and structure of Keyring after init', function(done){
        let prm = Gpgmejs.init({api_style: 'gpgme_openpgpjs'});
        prm.then(function (context) {
            expect(context.Keyring).to.be.an('object');
            expect(context.Keyring.getPublicKeys).to.be.a('function');
            expect(context.Keyring.deleteKey).to.be.a('function');
            expect(context.Keyring.getDefaultKey).to.be.a('function');
            done();
        });
    });
    // TODO: gpgme key interface not yet there
});

describe('Decrypting and verification in openpgp mode', function(){
    it('Decrypt', function(){
        let msg = openpgp.message.fromText(inputvalues.encryptedData);
        let prm = Gpgmejs.init({api_style: 'gpgme_openpgpjs'});
        prm.then(function (context) {
            context.decrypt({message: msg})
            .then(function(answer){
                expect(answer.data).to.be.a('string');
                expect(result.data).to.equal('¡Äußerste µ€ før ñoquis@hóme! Добрый день\n');
                done();
            });
        });
    });
    it('Decryption attempt with bad data returns gnupg error', function(done){
        let msg = openpgp.message.fromText(bigString(0.1));
        let prm = Gpgmejs.init({api_style: 'gpgme_openpgpjs'});
        prm.then(function (context) {
            context.decrypt({message: msg})
            .then( function(){},
            function(error){
                expect(error).to.be.an.instanceof(Error);
                expect(error.code).to.equal('GNUPG_ERROR');
                expect(error.message).to.be.a('string');
                // TBD: Type of error
                done();
            });
        });
    }).timeout(4000);
});
