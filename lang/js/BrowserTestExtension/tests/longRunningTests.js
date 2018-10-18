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
/* global describe, it, before, expect, Gpgmejs */
/* global bigString, inputvalues */

describe('Long running Encryption/Decryption', function () {
    let context = null;
    const good_fpr = inputvalues.encrypt.good.fingerprint;
    before(function (done){
        const prm = Gpgmejs.init({ timeout: 2000 });
        prm.then(function (gpgmejs){
            context = gpgmejs;
            done();
        });
    });

    for (let i=1; i < 101; i++) {
        it('Successful encrypt/decrypt completely random data '
            + (i) + '/100', function (done) {
            const data = bigString(2*1024*1024);
            context.encrypt({ data: data, publicKeys: good_fpr })
                .then(function (answer){
                    expect(answer).to.not.be.empty;
                    expect(answer.data).to.be.a('string');
                    expect(answer.data).to.include('BEGIN PGP MESSAGE');
                    expect(answer.data).to.include('END PGP MESSAGE');
                    context.decrypt({ data: answer.data })
                        .then(function (result){
                            expect(result).to.not.be.empty;
                            expect(result.data).to.be.a('string');
                            expect(result.data).to.equal(data);
                            done();
                        });
                });
        }).timeout(15000);
    }

});
