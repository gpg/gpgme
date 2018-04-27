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

import { expect } from "../node_modules/chai/chai";
import { GPGME_Message, createMessage } from "../src/Message";

import { message_params as mp, helper_params as hp} from "./inputvalues";

export function Messagetest(){

    describe('Message Object', function(){
        describe('correct initialization of an encrypt Message', function(){
            it('creating Message', function(){
                let test0 = createMessage('encrypt');
                expect(test0).to.be.an.instanceof(GPGME_Message);
                expect(test0.isComplete).to.be.false;
            });
            it('Message is complete after setting mandatoy data', function(){
                let test0 = createMessage('encrypt');
                test0.setParameter('data', mp.valid_encrypt_data);
                test0.setParameter('keys', hp.validFingerprints);
                expect(test0.isComplete).to.be.true;
            });
            it('Complete Message contains the data that was set', function(){
                let test0 = createMessage('encrypt');
                test0.setParameter('data', mp.valid_encrypt_data);
                test0.setParameter('keys', hp.validFingerprints);

                expect(test0.message).to.not.be.null;
                expect(test0.message).to.have.keys('op', 'data', 'keys');
                expect(test0.message.op).to.equal('encrypt');
                expect(test0.message.data).to.equal(
                    mp.valid_encrypt_data);
            });
        });

        describe('Incorrect initialization', function(){
            it('non-allowed operation', function(){
                let test0 = createMessage(mp.invalid_op_action);
                expect(test0).to.be.an.instanceof(Error);
                expect(test0.code).to.equal('MSG_WRONG_OP');
            });
            it('wrong parameter type in constructor', function(){
                let test0 = createMessage(mp.invalid_op_type);
                expect(test0).to.be.an.instanceof(Error);
                expect(test0.code).to.equal('PARAM_WRONG');
            });
        });

        describe('Setting wrong parameters', function(){
            it('Wrong parameter name', function(){
                let test0 = createMessage(mp.invalid_param_test.valid_op);
                for (let i=0; i < mp.invalid_param_test.invalid_param_names.length; i++){
                    let ret = test0.setParameter(
                        mp.invalid_param_test.invalid_param_names[i],
                        'Somevalue');
                    expect(ret).to.be.an.instanceof(Error);
                    expect(ret.code).to.equal('PARAM_WRONG');
                }
            });
            it('Wrong parameter value', function(){
                let test0 = createMessage(mp.invalid_param_test.valid_op);
                for (let j=0;
                    j < mp.invalid_param_test.invalid_values_0.length;
                    j++){
                        let ret = test0.setParameter(
                            mp.invalid_param_test.validparam_name_0,
                            mp.invalid_param_test.invalid_values_0[j]);
                        expect(ret).to.be.an.instanceof(Error);
                        expect(ret.code).to.equal('PARAM_WRONG');
                }
            });
        });
    });
}
export default Messagetest;