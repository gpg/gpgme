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
 *     Raimund Renkert <rrenkert@intevation.de>
 */

/* global describe, it, expect, Gpgmejs, ImportablePublicKey */

describe('Key importing', function () {
    it('Prepare test Key (deleting it from gnupg, if present)', function(done){
        let prm = Gpgmejs.init();
        prm.then(function (context) {
            expect(context.Keyring.getKeys).to.be.a('function');
            context.Keyring.getKeys(ImportablePublicKey.fingerprint).then(
                function(result){
                    if (result.length === 1) {
                        result[0].delete().then(function(result){
                            expect(result).to.be.true;
                            done();
                        });
                    } else {
                        done();
                    }
                });
        });
    });

    it('importing, updating, then deleting public Key', function (done) {
        //This test runs in one large step, to ensure the proper state of the
        // key in all stages.
        let prm = Gpgmejs.init();
        prm.then(function (context) {
            context.Keyring.getKeys(ImportablePublicKey.fingerprint).then(
                function(result){
                    expect(result).to.be.an('array');
                    expect(result.length).to.equal(0);
                    context.Keyring.importKey(ImportablePublicKey.key, true)
                        .then(function(result){
                            expect(result.Keys[0]).to.not.be.undefined;
                            expect(result.Keys[0].key).to.be.an('object');
                            expect(result.Keys[0].key.fingerprint).to.equal(
                                ImportablePublicKey.fingerprint);
                            expect(result.Keys[0].status).to.equal('newkey');
                            context.Keyring.importKey(
                                ImportablePublicKey.keyChangedUserId,true)
                                .then(function(res){
                                    expect(res.Keys[0]).to.not.be.undefined;
                                    expect(res.Keys[0].key).to.be.an('object');
                                    expect(res.Keys[0].key.fingerprint).to.equal(
                                        ImportablePublicKey.fingerprint);
                                    expect(res.Keys[0].status).to.equal(
                                        'change');
                                    expect(
                                        res.Keys[0].changes.userId).to.be.true;
                                    expect(
                                        res.Keys[0].changes.subkey).to.be.false;
                                    expect(
                                        res.Keys[0].changes.signature).to.be.true;
                                    res.Keys[0].key.delete().then(function(result){
                                        expect(result).to.be.true;
                                        done();
                                    });
                                });
                        });
                });
        });
    });

});