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
import "./node_modules/mocha/mocha";
import "./node_modules/chai/chai";
import { helper_params as hp } from "./unittest_inputvalues";
import { message_params as mp } from "./unittest_inputvalues";
import { whatever_params as wp } from "./unittest_inputvalues";
import { Connection } from "./src/Connection";
import { gpgme_error } from "./src/Errors";
import { toKeyIdArray , isFingerprint } from "./src/Helpers";
import { GPGME_Key , createKey } from "./src/Key";
import { GPGME_Keyring } from "./src/Keyring";
import {GPGME_Message, createMessage} from "./src/Message";
import { setTimeout } from "timers";

mocha.setup('bdd');
var expect = chai.expect;
chai.config.includeStack = true;

function unittests (){
    describe('Connection testing', function(){

        it('Connecting', function(done) {
            let conn0 = new Connection;
            let delayed = function(){
                expect(conn0.isConnected).to.be.true;
                expect(conn0.connect).to.be.a('function');
                expect(conn0.disconnect).to.be.a('function');
                expect(conn0.post).to.be.a('function');
                done();
            };
            setTimeout(delayed, 5);

        });

        it('Disconnecting', function(done) {
            let conn0 = new Connection;
            let delayed = function(){
                conn0.disconnect(); // TODO fails!
                expect(conn0.isConnected).to.be.false;
                done();
            };
            setTimeout(delayed, 5);
        });

        // broken
        // it('Connect info still only available after a delay', function(done){
        //     // if false, all delayed connections can be refactored
        //     let conn0 = new Connection;
        //     expect(conn0.isConnected).to.be.undefined;
        //  //
        // })
    });

    describe('Error Object handling', function(){

        it('check the Timeout error', function(){
            let test0 = gpgme_error('CONN_TIMEOUT');

            expect(test0).to.be.an.instanceof(Error);
            expect(test0.code).to.equal('CONN_TIMEOUT');
        });

        it('Error Object returns generic code if code is not listed', function(){
            let test0 = gpgme_error(hp.invalidErrorCode);

            expect(test0).to.be.an.instanceof(Error);
            expect(test0.code).to.equal('GENERIC_ERROR');
        });

        it('Warnings like PARAM_IGNORED should not return errors', function(){
            let test0 = gpgme_error('PARAM_IGNORED');

            expect(test0).to.be.null;
        });
    });

    describe('Fingerprint checking', function(){

        it('isFingerprint(): valid Fingerprint', function(){
            let test0  = isFingerprint(hp.validFingerprint);

            expect(test0).to.be.true;
        });

        it('isFingerprint(): invalid Fingerprints', function(){
            for (let i=0; i < hp.invalidFingerprints.length; i++){
                let test0 = isFingerprint(hp.invalidFingerprints[i]);

                expect(test0).to.be.false;
            }
        });
    });

    describe('toKeyIdArray() (converting input to fingerprint', function(){

        it('Correct fingerprint string', function(){
            let test0 = toKeyIdArray(hp.validFingerprint);

            expect(test0).to.be.an('array');
            expect(test0).to.include(hp.validFingerprint);
        });

        it('correct GPGME_Key', function(){
            expect(hp.validGPGME_Key).to.be.an.instanceof(GPGME_Key);
            let test0 = toKeyIdArray(hp.validGPGME_Key);

            expect(test0).to.be.an('array');
            expect(test0).to.include(hp.validGPGME_Key.fingerprint);
        });

        it('openpgpjs-like object', function(){
            let test0 = toKeyIdArray(hp.valid_openpgplike);

            expect(test0).to.be.an('array').with.lengthOf(1);
            console.log(test0);
            expect(test0).to.include(
                hp.valid_openpgplike.primaryKey.getFingerprint());
        });

        it('Array of valid inputs', function(){
            let test0 = toKeyIdArray(hp.validKeys);
            expect(test0).to.be.an('array');
            expect(test0).to.have.lengthOf(hp.validKeys.length);
        });

        it('Incorrect inputs', function(){

            it('valid Long ID', function(){
                let test0 = toKeyIdArray(hp.validLongId);

                expect(test0).to.be.empty;
            });

            it('invalidFingerprint', function(){
                let test0 = toKeyIdArray(hp.invalidFingerprint);

                expect(test0).to.be.empty;
            });

            it('invalidKeyArray', function(){
                let test0 = toKeyIdArray(hp.invalidKeyArray);

                expect(test0).to.be.empty;
            });

            it('Partially invalid array', function(){
                let test0 = toKeyIdArray(hp.invalidKeyArray_OneBad);

                expect(test0).to.be.an('array');
                expect(test0).to.have.lengthOf(
                    hp.invalidKeyArray_OneBad.length - 1);
            });
        });
    });

    describe('GPGME_Key', function(){

        it('correct Key initialization', function(){
            let conn = new Connection;
            let key = createKey(hp.validFingerprint, conn);

            expect(key).to.be.an.instanceof(GPGME_Key);
            expect(key.connection).to.be.an.instanceof(Connection);
            // TODO not implemented yet: Further Key functionality
        });

        it('Key can use the connection', function(){
            let conn = new Connection;
            let key = createKey(hp.validFingerprint, conn);

            expect(key.connection.isConnected).to.be.true;

            key.connection.disconnect();
            expect(key.connection.isConnected).to.be.false;
        });

        it('createKey returns error if parameters are wrong', function(){
            let conn = new Connection;
            for (let i=0; i< 4; i++){
                let key0 = createKey(wp.four_invalid_params[i], conn);

                expect(key0).to.be.an.instanceof(Error);
                expect(key0.code).to.equal('PARAM_WRONG');
            }
            for (let i=0; i< 4; i++){
                let key0 = createKey(
                    hp.validFingerprint, wp.four_invalid_params[i]);

                expect(key0).to.be.an.instanceof(Error);
                expect(key0.code).to.equal('PARAM_WRONG');
            }
        });
        it('bad GPGME_Key returns Error if used', function(){
            let conn = new Connection;
            for (let i=0; i < 4; i++){
                let key = new GPGME_Key(wp.four_invalid_params[i], conn);

                expect(key.connection).to.be.an.instanceof(Error);
                expect(key.connection.code).to.equal('KEY_INVALID');
            }
        });
    });

    describe('GPGME_Keyring', function(){

        it('correct initialization', function(){
            let conn = new Connection;
            let keyring = new GPGME_Keyring(conn);

            expect(keyring).to.be.an.instanceof(GPGME_Keyring);
            expect(keyring.connection).to.be.an.instanceof(Connection);
            expect(keyring.getKeys).to.be.a('function');
            expect(keyring.getSubset).to.be.a('function');
        });

        it('Keyring should return errors if not connected', function(){
            let keyring = new GPGME_Keyring;

            expect(keyring).to.be.an.instanceof(GPGME_Keyring);
            expect(keyring.connection).to.be.an.instanceof(Error);
            expect(keyring.connection.code).to.equal('CONN_NO_CONNECT');
            expect(keyring.getKeys).to.be.an.instanceof(Error);
            expect(keyring.getkeys.code).to.equal('CONN_NO_CONNECT');
        });
            //TODO not yet implemented:
            //  getKeys(pattern, include_secret) //note: pattern can be null
            //  getSubset(flags, pattern)
                // available Boolean flags: secret revoked expired
    });

    describe('GPGME_Message', function(){

        it('creating encrypt Message', function(){
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

        it ('Not accepting non-allowed operation', function(){
            let test0 = createMessage(mp.invalid_op_action);

            expect(test0).to.be.an.instanceof(Error);
            expect(test0.code).to.equal('MSG_WRONG_OP');
        });
        it('Not accepting wrong parameter type', function(){
            let test0 = createMessage(mp.invalid_op_type);

            expect(test0).to.be.an.instanceof(Error);
            expect(test0.code).to.equal('PARAM_WRONG');
        });

        it('Not accepting wrong parameter name', function(){
            let test0 = createMessage(mp.invalid_param_test.valid_op);
            for (let i=0;
                i < mp.invalid_param_test.invalid_param_names.length; i++){
                    let ret = test0.setParameter(
                        mp.invalid_param_test.invalid_param_names[i],
                        'Somevalue');

                    expect(ret).to.be.an.instanceof(Error);
                    expect(ret.code).to.equal('PARAM_WRONG');
            }
        });

        it('Not accepting wrong parameter value', function(){
            let test0 = createMessage(mp.invalid_param_test.valid_op);
            for (let j=0;
                j < mp.invalid_param_test.invalid_values_0.length; j++){
                    let ret = test0.setParameter(
                        mp.invalid_param_test.validparam_name_0,
                        mp.invalid_param_test.invalid_values_0[j]);

                    expect(ret).to.be.an.instanceof(Error);
                    expect(ret.code).to.equal('PARAM_WRONG');
            }
        });
    });

    mocha.run();
}

export default {unittests};