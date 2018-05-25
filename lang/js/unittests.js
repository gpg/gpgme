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
import { key_params as kp } from "./unittest_inputvalues";
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
            conn0.checkConnection().then(function(answer) {
                expect(answer).to.not.be.empty;
                expect(answer.gpgme).to.not.be.undefined;
                expect(answer.gpgme).to.be.a('string');
                expect(answer.info).to.be.an('Array');
                expect(conn0.disconnect).to.be.a('function');
                expect(conn0.post).to.be.a('function');
                conn0.disconnect();
                done();
            });

        });

        it('Disconnecting', function(done) {
            let conn0 = new Connection;
            conn0.checkConnection(false).then(function(answer) {
                expect(answer).to.be.true;
                conn0.disconnect();
                conn0.checkConnection(false).then(function(result) {
                    expect(result).to.be.false;
                    done();
                });
            });
        });
    });

    describe('Error Object handling', function(){
        // TODO: new GPGME_Error codes
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

    describe('toKeyIdArray() (converting input to fingerprint)', function(){

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
            let key = createKey(kp.validKeyFingerprint, conn);
            expect(key).to.be.an.instanceof(GPGME_Key);
            expect(key.connection).to.be.an.instanceof(Connection);
            conn.disconnect();
        });
        it('Key has data after a first refresh', function(done) {
            let conn = new Connection;
            let key = createKey(kp.validKeyFingerprint, conn);
            key.refreshKey().then(function(key2){
                expect(key2).to.be.an.instanceof(GPGME_Key);
                expect(key2.get).to.be.a('function');
                for (let i=0; i < kp.validKeyProperties.length; i++) {
                    let prop = key2.get(kp.validKeyProperties[i]);
                    expect(prop).to.not.be.undefined;
                    expect(prop).to.be.a('boolean');
                }
                expect(isFingerprint(key2.get('fingerprint'))).to.be.true;
                expect(
                    key2.get('fingerprint')).to.equal(kp.validKeyFingerprint);
                expect(
                    key2.get('fingerprint')).to.equal(key.fingerprint);
                conn.disconnect();
                done();
            });
        });

        it('Non-cached key async data retrieval', function (done){
            let conn = new Connection;
            let key = createKey(kp.validKeyFingerprint, conn);
            key.get('can_authenticate',false).then(function(result){
                expect(result).to.be.a('boolean');
                conn.disconnect();
                done();
            });
        })

        it('Querying non-existing Key returns an error', function(done) {
            let conn = new Connection;
            let key = createKey(kp.invalidKeyFingerprint, conn);
            key.refreshKey().then(function(){},
                function(error){
                    expect(error).to.be.an.instanceof(Error);
                    expect(error.code).to.equal('KEY_NOKEY');
                    conn.disconnect();
                    done();
            });
        });


        it('Key can use the connection', function(done){
            let conn = new Connection;
            let key = createKey(hp.validFingerprint, conn);
            key.connection.checkConnection(false).then(function(result){
                expect(result).to.be.true;
                key.connection.disconnect();
                key.connection.checkConnection(false).then(function(result2){
                    expect(result2).to.be.false;
                    conn.disconnect();
                    done();
                });
            });
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
            conn.disconnect();
        });

        it('malformed GPGME_Key cannot be used', function(){
            let conn = new Connection;
            for (let i=0; i < 4; i++){
                let key = new GPGME_Key(wp.four_invalid_params[i], conn);
                expect(key.fingerprint).to.be.an.instanceof(Error);
                expect(key.fingerprint.code).to.equal('KEY_INVALID');
            }
            conn.disconnect();
        });

        // TODO: tests for subkeys
        // TODO: tests for userids
        // TODO: some invalid tests for key/keyring
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
            // not yet implemented:
            // keyring.getKeys().then(
                // function(result){},
                //function(reject){
                    // expect(reject).to.be.an.instanceof(Error);
                    // done();
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

        it('Message is complete after setting mandatory data', function(){
            let test0 = createMessage('encrypt');
            test0.setParameter('data', mp.valid_encrypt_data);
            test0.setParameter('keys', hp.validFingerprints);

            expect(test0.isComplete).to.be.true;
        });

        it('Message is not complete after mandatory data is empty', function(){
            let test0 = createMessage('encrypt');
            test0.setParameter('data', '');
            test0.setParameter('keys', hp.validFingerprints);
            expect(test0.isComplete).to.be.false;
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

}

export default {unittests};