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
            // Fingerprint of a key that has been imported to gnupg (i.e. see testkey.pub; testkey.sec)
            fingerprint : 'D41735B91236FDB882048C5A2301635EEFF0CB05',
            data_nonascii: '¡Äußerste µ€ før ñoquis@hóme! Добрый день',

            // used for checking encoding consistency in > 2MB messages.
            data_nonascii_32: [
                'K€K€K€K€K€K€K€K€K€K€K€K€K€K€K€K€',
                'µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€',
                '€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€',
                '²³²³²³²³²³²³²³²³²³²³²³²³²³²³²³²³',
                'µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€A€µ€µ€µ€µ€',
                'µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€µ€µAµ€µ€µ€µ€',
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
            // valid Hex value, but not usable (not imported to gnupg, or bogus fingerprint)
            fingerprint: 'CDC3A2B2860625CCBFC5AAAAAC6D1B604967FC4A'
        }
    },
    init: {
        // some parameters
        invalid_startups: [
            {all_passwords: true},
            'openpgpmode',
            {api_style:"frankenstein"}
        ]
    }
};

// (Pseudo-)Random String from a Uint8Array, given approx. size in Megabytes
function bigString(megabytes){
    let maxlength = 1024 * 1024 * megabytes;
    let uint = new Uint8Array(maxlength);
    for (let i= 0; i < maxlength; i++){
        uint[i] = Math.random() * Math.floor(256);
    }
    return new TextDecoder('utf-8').decode(uint);
}

// (Pseudo-)Random Uint8Array, given size in Megabytes
function bigUint8(megabytes){
    let maxlength = 1024 * 1024 * megabytes;
    let uint = new Uint8Array(maxlength);
    for (let i= 0; i < maxlength; i++){
        uint[i] = Math.random() * Math.floor(256);
    }
    return uint;
}

// (Pseudo-)Random string with very limited charset (ascii only, no control chars)
function bigBoringString(megabytes){
    let maxlength = 1024 * 1024 * megabytes;
    let string = '';
    let chars = ' 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    for (let i= 0; i < maxlength; i++){
        string = string + chars[Math.floor(Math.random() * chars.length)];
    }
    return string;
}

// Some String with simple chars, with different characteristics, but still
// expected to occur in an averag message
function slightlyLessBoringString(megabytes, set){
    let maxlength = 1024 * 1024 * megabytes;
    let string = '';
    let chars = '';
    if (set ===1 ) {
        chars = '\n\"\r \'';
    } else if (set === 2 ) {
        chars = '()=?`#+-{}[]';
    } else if (set === 3){
        chars = '^°/';
    } else if (set ===4) {
        chars = 'äüßµüþÖ~ɁÑ||@';
    } else {
        chars = '*<>\n\"\r§$%&/()=?`#+-{}[] \'';
    }
    for (let i= 0; i < maxlength; i++){
        string = string + chars[Math.floor(Math.random() * chars.length)];
    }
    return string;
}

// Data encrypted with testKey
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
