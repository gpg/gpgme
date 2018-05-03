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
describe('Encryption', function(){
    it('Successfull encrypt', function(){
        let prm = Gpgmejs.init();
        prm.then(function(context){
            context.encrypt(
            inputvalues.encrypt.good.data,
            inputvalues.encrypt.good.fingerprint).then(function(answer){
                    expect(answer).to.not.be.empty;
                    expect(answer.data).to.be.a("string");
                    expect(answer.data).to.include('BEGIN PGP MESSAGE');
                    expect(answer.data).to.include('END PGP MESSAGE');
                });
        });
    });

    it('Sending encryption without keys fails', function(){
        let prm = Gpgmejs.init();
        prm.then(function(context){
            context.encrypt(
                inputvalues.encrypt.good.data,
                null).then(function(answer){
                    expect(answer).to.be.undefined;
                }, function(error){
                    expect(error).to.be.an('Error');
                    expect(error.code).to.equal('MSG_INCOMPLETE');
                    //TODO: MSG_INCOMPLETE desired, GNUPG_ERROR coming
                });
        });
    });

    it('Sending encryption without data fails', function(){
        let prm = Gpgmejs.init();
        prm.then(function(context){
            context.encrypt(
                null,inputvalues.encrypt.good.keyid).then(function(answer){
                    expect(answer).to.be.undefined;
                }, function(error){
                    expect(error).to.be.an.instanceof(Error);
                    expect(error.code).to.equal('PARAM_WRONG');
                });
        });
    });
    // TODO check different valid parameter
});
