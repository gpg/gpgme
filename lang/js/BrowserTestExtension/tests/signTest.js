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
/* global bigString, inputvalues */

describe('Signing', function () {
    it('Sign a message', function (done) {
        let prm = Gpgmejs.init();
        prm.then(function (context) {
            let data = bigString(100);
            context.sign(
                data,
                inputvalues.encrypt.good.fingerprint).then(function (answer) {
                expect(answer).to.not.be.empty;
                expect(answer.data).to.be.a('string');
                expect(answer.data).to.include('BEGIN PGP SIGNATURE');
                expect(answer.data).to.include('END PGP SIGNATURE');
                expect(answer.data).to.include(data);
                done();
            });
        });
    });
    it('Detached sign a message', function (done) {
        let prm = Gpgmejs.init();
        prm.then(function (context) {
            let data = bigString(100);
            context.sign(
                data,
                inputvalues.encrypt.good.fingerprint,
                'detached'
            ).then(function (answer) {
                expect(answer).to.not.be.empty;
                expect(answer.data).to.be.a('string');
                expect(answer.data).to.include(data);
                expect(answer.signature).to.be.a('string');
                expect(answer.signature).to.be.a('string');
                done();
            });
        });
    });

});
