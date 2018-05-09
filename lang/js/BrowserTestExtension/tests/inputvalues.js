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

var inputvalues = {
    encrypt: {
        good:{
            data : 'Hello World.',
            fingerprint : 'D41735B91236FDB882048C5A2301635EEFF0CB05',
            data_nonascii: '¡Äußerste µ€ før ñoquis@hóme! Добрый день',
            data_nonascii_32: [
                'K€K€K€K€K€K€K€K€K€K€K€K€K€K€K€K€',
                'µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€', //fails result has 3 chars more
                '€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€', //fails 3 chars
                '²³²³²³²³²³²³²³²³²³²³²³²³²³²³²³²³',
                'µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€A€µ€µ€µ€µ€', //fails 2 chars
                'µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€µAµ€µ€µ€µ€', //is okay if 2 chunksizes.
                'üüüüüüüüüüüüüüüüüüüüüüüüüüüüüüüü',
                'µAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA€',
                'µAAAAµAAAAAAAAAAAAAAAAAAAAAAAAA€',
                'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAµ€',
                'µAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA°',
                '€AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA€',
                'µ||||||||||||||||||||||||||||||€',
                'æſæſ³¼„¬“³³¬“¬½”æſæſ³¼„¬“³³¬“¬½”'
            ]
        },
        bad: {
            fingerprint: 'CDC3A2B2860625CCBFC5AAAAAC6D1B604967FC4A'
        }
    },
    init: {
        invalid_startups: [{all_passwords: true}, 'openpgpmode', {api_style:"frankenstein"}]
    }

};

function bigString(megabytes){
    let maxlength = 1024 * 1024 * megabytes;
    let uint = new Uint8Array(maxlength);
    for (let i= 0; i < maxlength; i++){
        uint[i] = Math.random() * Math.floor(256);
    }
    return new TextDecoder('utf-8').decode(uint);
}

function bigUint8(megabytes){
    let maxlength = 1024 * 1024 * megabytes;
    let uint = new Uint8Array(maxlength);
    for (let i= 0; i < maxlength; i++){
        uint[i] = Math.random() * Math.floor(256);
    }
    return uint;
}

function bigBoringString(megabytes){
    let maxlength = 1024 * 1024 * megabytes;
    let string = '';
    let chars = ' 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    for (let i= 0; i < maxlength; i++){
        string = string + chars[Math.floor(Math.random() * chars.length)];
    }
    return string;
}

function slightlyLessBoringString(megabytes, set){
    let maxlength = 1024 * 1024 * megabytes;
    let string = '';
    let chars = '';
    if (!set){

    } else if (set ===1 ) {
        chars = '\n\"\r \'';
    } else if (set === 2 ) {
        chars = '()=?`#+-{}[]';
    } else if (set === 3){
        chars = '^°/';
            //'*<>\\^°/';
    } else if (set ===4) {
        chars = 'äüßµüþÖ~ɁÑ||@';
    } else {
        chars = '*<>\n\"\r§$%&/()=?`#+-{}[] \''; //fails!

    }
    for (let i= 0; i < maxlength; i++){
        string = string + chars[Math.floor(Math.random() * chars.length)];
    }
    return string;
}

var encryptedData =
    '-----BEGIN PGP MESSAGE-----\n' +
    '\n' +
    'hQEMA6B8jfIUScGEAQgAlANd3uyhmhYLzVcfz4LEqA8tgUC3n719YH0iuKEzG/dv\n' +
    'B8fsIK2HoeQh2T3/Cc2LBMjgn4K33ksG3k2MqrbIvxWGUQlOAuggc259hquWtX9B\n' +
    'EcEoOAeh5DuZT/b8CM5seJKNEpPzNxbEDiGikp9DV9gfIQTTUnrDjAu5YtgCN9vA\n' +
    '3PJxihioH8ODoQw2jlYSkqgXpBVP2Fbx7qgTuxGNu5w36E0/P93//4hDXcKou7ez\n' +
    'o0+NEGSkbaY+OPk1k7k9n+vBSC3F440dxsTNs5WmRvx9XZEotJkUBweE+8XaoLCn\n' +
    '3RrtyD/lj63qi3dbyI5XFLuPU1baFskJ4UAmI4wNhdJ+ASailpnFBnNgiFBh3ZfB\n' +
    'G5Rmd3ocSL7l6lq1bVK9advXb7vcne502W1ldAfHgTdQgc2CueIDFUYAaXP2OvhP\n' +
    'isGL7jOlDCBKwep67ted0cTRPLWkk3NSuLIlvD5xs6L4z3rPu92gXYgbZoMMdP0N\n' +
    'kSAQYOHplfA7YJWkrlRm\n' +
    '=zap6\n' +
    '-----END PGP MESSAGE-----\n';
var encryptedBroken = '-----BEGIN PGP MESSAGE-----\n' +
'\n' +
'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\n' +
'E14StpggdK8=\n' +
'=enm3\n' +
'-----END PGP MESSAGE-----\n';