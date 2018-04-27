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
import { gpgme_error} from "../src/Errors";
import { GPGME_Key } from "../src/Key";
import { isLongId, isFingerprint, toKeyIdArray } from "../src/Helpers"
import { helper_params } from "./inputvalues";

export function Helpertest(){
    describe('Error Object handling', function(){
        it('check the Timeout error', function(){
            let test0 = gpgme_error('CONN_TIMEOUT');
            expect(test0).to.be.an.instanceof(Error);
            expect(test0.code).to.equal('CONN_TIMEOUT');
        });
        it('Error Object returns generic code if code is not listed', function(){
            let test0 = gpgme_error(helper_params.invalidErrorCode);
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
            let test0  = isFingerprint(helper_params.validFingerprint);
            expect(test0).to.be.true;
        });
        it('isFingerprint(): invalid Fingerprint', function(){
            let test0 = isFingerprint(helper_params.invalidFingerprint);
            expect(test0).to.be.false;
        });
    });
    describe('Converting to Fingerprint', function(){
        it('Correct Inputs', function(){
            it('Fingerprint string', function(){
                let test0 = toKeyIdArray(helper_params.validFingerprint);
                expect(test0).to.be.an('array');
                expect(test0).to.include(helper_params.validFingerprint);
            });
            it('GPGME_Key', function(){
                expect(helper_params.validGPGME_Key).to.be.an.instanceof(GPGME_Key);
                let test0 = toKeyIdArray(helper_params.validGPGME_Key);
                expect(test0).to.be.an('array');
                expect(test0).to.include(helper_params.validGPGME_Key.fingerprint);
            });
            it('Array of valid inputs', function(){
                let test0 = toKeyIdArray(helper_params.validKeys);
                expect(test0).to.be.an('array');
                expect(test0).to.have.lengthOf(helper_params.validKeys.length);
            });
        });
        describe('Incorrect inputs', function(){
            it('valid Long ID', function(){
                let test0 = toKeyIdArray(helper_params.validLongId);
                expect(test0).to.be.empty;
            });
            it('invalidFingerprint', function(){
                let test0 = toKeyIdArray(helper_params.invalidFingerprint);
                expect(test0).to.be.empty;
            });
            it('invalidKeyArray', function(){
                let test0 = toKeyIdArray(helper_params.invalidKeyArray);
                expect(test0).to.be.empty;
            });
            it('Partially invalid array', function(){
                let test0 = toKeyIdArray(helper_params.invalidKeyArray_OneBad);
                expect(test0).to.be.an('array');
                expect(test0).to.have.lengthOf(
                    helper_params.invalidKeyArray_OneBad.length - 1);
            });
        });
    });
};
export default Helpertest;