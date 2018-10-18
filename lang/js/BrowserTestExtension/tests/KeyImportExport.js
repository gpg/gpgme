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
 *     Raimund Renkert <rrenkert@intevation.de>
 */

/* global describe, it, expect, before, afterEach, Gpgmejs*/
/* global ImportablePublicKey, inputvalues */

describe('Key importing', function () {
    const fpr = ImportablePublicKey.fingerprint;
    const pubKey = ImportablePublicKey.key;
    const changedKey = ImportablePublicKey.keyChangedUserId;

    let context = null;
    before(function (done){
        const prm = Gpgmejs.init({ timeout: 2000 });
        prm.then(function (gpgmejs){
            context = gpgmejs;
            context.Keyring.getKeys({ pattern: fpr }).then(
                function (result){
                    if (result.length === 1) {
                        result[0].delete().then(function (){
                            done();
                        },function (){
                            done();
                        });
                    } else {
                        done();
                    }
                });
        });
    });

    afterEach(function (done){
        // delete the test key if still present
        context.Keyring.getKeys({ pattern: fpr }).then(
            function (result){
                if (result.length === 1) {
                    result[0].delete().then(function (){
                        done();
                    },function (){
                        done();
                    });
                } else {
                    done();
                }
            });
    });

    it('Importing Key', function (done) {
        context.Keyring.getKeys({ pattern: fpr }).then(function (result){
            expect(result).to.be.an('array');
            expect(result.length).to.equal(0);
            context.Keyring.importKey(pubKey).then(function (result){
                expect(result.Keys).to.be.an('array');
                expect(result.Keys[0]).to.not.be.undefined;
                expect(result.Keys[0].key).to.be.an('object');
                expect(result.Keys[0].key.fingerprint).to.equal(fpr);
                expect(result.Keys[0].status).to.equal('newkey');
                expect(result.summary.considered).to.equal(1);
                expect(result.summary.imported).to.equal(1);
                done();
            });
        });
    });

    it('Updating Key', function (done){
        context.Keyring.importKey(pubKey)
            .then(function (result){
                expect(result.Keys[0].key).to.not.be.undefined;
                expect(result.Keys[0].status).to.equal('newkey');
                context.Keyring.importKey(changedKey).then(function (res){
                    expect(res.Keys[0].key).to.be.an('object');
                    expect(res.Keys[0].key.fingerprint).to.equal(fpr);
                    expect(res.Keys[0].status).to.equal('change');
                    expect(res.Keys[0].changes.userId).to.be.true;
                    expect(res.Keys[0].changes.subkey).to.be.false;
                    expect(res.Keys[0].changes.signature).to.be.true;
                    expect(res.summary.considered).to.equal(1);
                    done();
                });
            });
    });

    it('Deleting Key', function (done) {
        context.Keyring.importKey(pubKey).then(function (result){
            expect(result.Keys[0].key).to.be.an('object');
            expect(result.Keys[0].key.fingerprint).to.equal(fpr);
            result.Keys[0].key.delete().then(function (result){
                expect(result).to.be.true;
                done();
            });
        });
    });

    it('Import result feedback', function (done){
        context.Keyring.importKey(pubKey, true).then(function (result){
            expect(result).to.be.an('object');
            expect(result.Keys[0]).to.be.an('object');
            expect(result.Keys[0].key.fingerprint).to.equal(fpr);
            expect(result.Keys[0].status).to.equal('newkey');
            result.Keys[0].key.getArmor().then(function (armor){
                expect(armor).to.be.a('string');
                done();
            });
        });
    });

    it('exporting armored Key with getKeysArmored', function (done) {
        context.Keyring.importKey(pubKey).then(function (){
            context.Keyring.getKeysArmored({ pattern: fpr })
                .then(function (result){
                    expect(result).to.be.an('object');
                    expect(result.armored).to.be.a('string');
                    expect(result.secret_fprs).to.be.undefined;
                    done();
                });
        });
    });

    it('Exporting Key (including secret fingerprints)', function (done) {
        const key_secret = inputvalues.encrypt.good.fingerprint;
        context.Keyring.getKeysArmored({
            pattern: key_secret, with_secret_fpr: true })
            .then(function (result){
                expect(result).to.be.an('object');
                expect(result.armored).to.be.a('string');
                expect(result.secret_fprs).to.be.an('array');
                expect(result.secret_fprs[0]).to.equal(key_secret);
                done();
            });
    });
});