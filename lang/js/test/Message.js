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

import { message_params } from "./inputvalues";

function Messagetest(){

    describe('Message Object', function(){
        describe('incorrect initialization', function(){
            it('non-allowed operation', function(){
                let test0 = createMessage(message_params.invalid_op_action);
                expect(test0).to.be.an.instanceof(Error);
                expect(test0.code).to.equal('MSG_WRONG_OP');
            });
            it('wrong parameter type in constructor', function(){
                let test0 = createMessage(message_params.invalid_op_type);
                expect(test0).to.be.an.instanceof(Error);
                expect(test0.code).to.equal('PARAM_WRONG');
            });
        });
    });
};
export default Messagetest;