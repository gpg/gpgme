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

/* global describe, it, expect, bigString, inputvalues, Gpgmejs */

let verifyData = {
    signedMessage: '-----BEGIN PGP SIGNED MESSAGE-----\n' +
    'Hash: SHA256\n' +
    '\n' +
    'Matschige Münsteraner Marshmallows\n' +
    '-----BEGIN PGP SIGNATURE-----\n' +
    '\n' +
    'iQEzBAEBCAAdFiEE34YHmHCyv9oBiN3shwTx6WpaVdQFAlsqWxYACgkQhwTx6Wpa\n' +
    'VdRaTQf9Fj8agQzbE6DtonewZVGzj1KmjjpyAypnDldY21lrN8zIaQ+aKqRVkVrV\n' +
    '5A/MeUfoHh0b/9G1Co4LOuNjGS14GRNlFvPtxeA2mCwlk7kgP2i6ekbHdEXWcG9c\n' +
    'gSbzdJ3EgfVCFNkC/yhldXSLOJZ7oyiGEteDpi8dDSa9dIprT++sQ4kRuR8jPrIi\n' +
    'UUY+DltG3it7PybcTFfQm53I0mtnpFsizzCmgyJAkfG5fwVL3uWwbYGofD049PSu\n' +
    '6IEkSY74r8JbAbkCOiF/ln40RYGSwM0Ta5rrb3A3MixZNL/a1r17oljkaWz8e8VT\n' +
    'N7NUgBHwbIQ4e3RLuUU8fF3ICCGDOw==\n' +
    '=oGai\n' +
    '-----END PGP SIGNATURE-----\n'
};

describe('Verify data', function () {
    it('Successful verify message', function (done) {
        let message = verifyData.signedMessage;
        let prm = Gpgmejs.init();
        prm.then(function (context) {
            context.verify(message).then(function(result){
                expect(result.data).to.be.a('string');
                expect(result.all_valid).to.be.true;
                expect(result.count).to.equal(1);
                expect(result.signatures.good).to.be.an('array');
                expect(result.signatures.good.length).to.equal(1);
                expect(result.signatures.good[0].fingerprint)
                    .to.be.a('string');
                expect(result.signatures.good[0].valid).to.be.true;
                done();
            });
        });
    });

    it('Encrypt-Sign-Verify random message', function (done) {
        let message = bigString(2000);
        let fpr = inputvalues.encrypt.good.fingerprint;
        let prm = Gpgmejs.init();
        prm.then(function (context) {
            context.encrypt(message, fpr).then(function(message_enc){
                context.sign(message_enc.data, fpr).then(function(message_encsign){
                    context.verify(message_encsign.data).then(function(result){
                        expect(result.data).to.equal(message_enc.data);
                        expect(result.data).to.be.a('string');
                        expect(result.all_valid).to.be.true;
                        expect(result.count).to.equal(1);
                        expect(result.signatures.good).to.be.an('array');
                        expect(result.signatures.good.length).to.equal(1);
                        expect(result.signatures.good[0].fingerprint)
                            .to.equal(fpr);
                        expect(result.signatures.good[0].valid).to.be.true;
                        done();
                    });
                });
            });
        });
    });
});