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
    'iQEzBAEBCAAdFiEE1Bc1uRI2/biCBIxaIwFjXu/wywUFAltRoiMACgkQIwFjXu/w\n' +
    'ywUvagf6ApQbZbTPOROqfTfxAPdtzJsSDKHla6D0G5wom2gJbAVb0B2YS1c3Gjpq\n' +
    'I4kTKT1W1RRkne0mK9cexf4sjb5DQcV8PLhfmmAJEpljDFei6i/E309BvW4CZ4rG\n' +
    'jiurf8CkaNkrwn2fXJDaT4taVCX3V5FQAlgLxgOrm1zjiGA4mz98gi5zL4hvZXF9\n' +
    'dHY0jLwtQMVUO99q+5XC1TJfPsnteWL9m4e/YYPfYJMZZso+/0ib/yX5vHCk7RXH\n' +
    'CfhY40nMXSYdfl8mDOhvnKcCvy8qxetFv9uCX06OqepAamu/bvxslrzocRyJ/eq0\n' +
    'T2JfzEN+E7Y3PB8UwLgp/ZRmG8zRrQ==\n' +
    '=ioB6\n' +
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