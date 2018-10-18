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

const inputvalues = {// eslint-disable-line no-unused-vars
    encrypt: {
        good:{
            data : 'Hello World.',
            // Fingerprint of a key that has been imported to gnupg
            // (i.e. see testkey.pub; testkey.sec)
            fingerprint : 'D41735B91236FDB882048C5A2301635EEFF0CB05',
            fingerprint_mixedcase: 'D41735B91236fdb882048C5A2301635eeFF0Cb05',
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
            // valid Hex value, but not usable (not imported to gnupg, or
            // bogus fingerprint)
            fingerprint: 'CDC3A2B2860625CCBFC5AAAAAC6D1B604967FC4A'
        }
    },

    signedMessage: {
        good: '-----BEGIN PGP SIGNED MESSAGE-----\n' +
        'Hash: SHA256\n' +
        '\n' +
        'Matschige Münsteraner Marshmallows\n' +
        '-----BEGIN PGP SIGNATURE-----\n' +
        '\n' +
        'iQEzBAEBCAAdFiEE1Bc1uRI2/biCBIxaIwFjXu/wywUFAltRoiMACgkQIwFjXu/w\n' +
        'ywUvagf6ApQbZbTPOROqfTfxAPdtzJsSDKHla6D0G5wom2gJbAVb0B2YS1c3Gjpq\n' +
        'I4kTKT1W1RRkne0mK9cexf4sjb5DQcV8PLhfmmAJEpljDFei6i/E309BvW4CZ4rG\n' +
        'jiurf8CkaNkrwn2fXJDaT4taVCX3V5FQAlgLxgOrm1zjiGA4mz98gi5zL4hvZXF9\n' +
        'dHY0jLwtQMVUO99q+5XC1TJfPsnteWL9m4e/YYPfYJMZZso+/0ib/yX5vHCk7RXH\n' +
        'CfhY40nMXSYdfl8mDOhvnKcCvy8qxetFv9uCX06OqepAamu/bvxslrzocRyJ/eq0\n' +
        'T2JfzEN+E7Y3PB8UwLgp/ZRmG8zRrQ==\n' +
        '=ioB6\n' +
        '-----END PGP SIGNATURE-----\n',
        bad: '-----BEGIN PGP SIGNED MESSAGE-----\n' +
        'Hash: SHA256\n' +
        '\n' +
        'Matschige Münchener Marshmallows\n' +
        '-----BEGIN PGP SIGNATURE-----\n' +
        '\n' +
        'iQEzBAEBCAAdFiEE1Bc1uRI2/biCBIxaIwFjXu/wywUFAltRoiMACgkQIwFjXu/w\n' +
        'ywUvagf6ApQbZbTPOROqfTfxAPdtzJsSDKHla6D0G5wom2gJbAVb0B2YS1c3Gjpq\n' +
        'I4kTKT1W1RRkne0mK9cexf4sjb5DQcV8PLhfmmAJEpljDFei6i/E309BvW4CZ4rG\n' +
        'jiurf8CkaNkrwn2fXJDaT4taVCX3V5FQAlgLxgOrm1zjiGA4mz98gi5zL4hvZXF9\n' +
        'dHY0jLwtQMVUO99q+5XC1TJfPsnteWL9m4e/YYPfYJMZZso+/0ib/yX5vHCk7RXH\n' +
        'CfhY40nMXSYdfl8mDOhvnKcCvy8qxetFv9uCX06OqepAamu/bvxslrzocRyJ/eq0\n' +
        'T2JfzEN+E7Y3PB8UwLgp/ZRmG8zRrQ==\n' +
        '=ioB6\n' +
        '-----END PGP SIGNATURE-----\n'
    },
    encryptSignedMessage: '-----BEGIN PGP MESSAGE-----\n'+
        '\n'+
        'hQEMA6B8jfIUScGEAQf/bmQ+xNMGTjPvQCktkxR4Svt2dVNVdSzKsCmvSv24QOQF\n'+
        'yBMK5w51S/6DTdiZI12IYD7hjvkr9NqxXXupjrVKwqEVpg4Pkwckac0OcElJIBsL\n'+
        '3htr4iYsr8dhSgSS4BO0azcu4wZQTXy5v2P7yYPECMEagNEXnW+tE7sHLCq8Ysqz\n'+
        'LVxG0R0IUijKeEd3xQC2Tt20e1Z1j5tnqaPhE/9Smqf5OjSUDqpXxvRnSNRk/zEs\n'+
        'cGVgCF+cv68nUJM9lwEAbBQChplwL6ebnhunC6DsRCxnjLHVyKm127hmhSiMGC0e\n'+
        'Ns31mGeP1dxpDv6Gi2/oKmq67vG3i4fKeckj7bt30tLA1wH0Qn5Mn6Tzxzve0W0q\n'+
        'Ghqn9PY9qNK8EkrkzqaFk9dzu5tfSbaJBLS/uIhX2Wj70EMEBbFSkN0qlgOfLgGw\n'+
        '5mwRvCgj4nvV1ByFhnx7uwgQixvOwLH4JLKvwCQpJm+O2R0eC7M6CzR/b9iL/oaO\n'+
        'JTkoD9hcLhxF7j+3ZYg7rbNwofuHST097vFjzItsucb0jHOzjlkCqbhdczICILTa\n'+
        'H76Q6YGdMLyG9a3s4yZUMruaeQyWGeXlryzLDvdEoSgoD5YrolsFOM+Z2apbzVs2\n'+
        'k5CltwtanjjWGnpAqSyr49C6CSU8G1QHpNygx5frtAS8bojR2ovB9OJp2wUklDvC\n'+
        'LtU7dLpTY/BIvfB1vzwcW/aNgmPadNHX8mAzlqTQJjeLoo69Wp804t+u36sgfd/J\n'+
        'ser7vdJJUm+86Q9csefItvFmHhqjMg5XXHoa8WZWJOHIQMxZkaIwKAzcEt/oEOdJ\n'+
        'rbVNVabhTdbmS5I1ok16wg5jMF07ZDM7nXWMcQNjwT646XKP+pp2N6YQROVidNXj\n'+
        'COyRyiXE/csr\n'+
        '=Ik7G\n'+
        '-----END PGP MESSAGE-----\n',
    someInputParameter: 'bad string',

    publicKeyNonAscii: {
        userid: 'Müller €uro',
        key: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n' + '\n' +
          'mQENBFt2/VIBCADIWBIMxExZlHda4XIVnM9nsIfUYLebJSC/krEriyWgzytU8/fQ\n' +
          'S05cfnYx7RXvOOq4k8aa7mu80ovg3q77idXauLreAUwng4Njw0nMxWq/vtoMiZ60\n' +
          '9f8EmfthZophhkQF2HIPHyqXMDZzMLWv4oTr2UJ9BKudL1XtbK51y9TbiyfQygBl\n' +
          '8bl+zrOo70/dN6aunvuo6Hlu5cEzkj2QrzZlqTdfG5qv6KVEMut1eAbxZAmvSnna\n' +
          'R4wqiRCT3/eRXGJbDL/8GaCEYkwi9FBrimjOTV0MpcLNwAU4aGfDxMUsxML9xJ+/\n' +
          '/6GFxzYf7Lmk5UhvoewR58uQkHkTVPjZ9hXZABEBAAG0KE3DvGxsZXIg4oKsdXJv\n' +
          'IDxtdWVsbGVyZXVyb0BleGFtcGxlLm9yZz6JAVQEEwEIAD4WIQQVNixp3XT/DuGT\n' +
          'F4MFmkL4L5UZdAUCW3b9UgIbAwUJA8JnAAULCQgHAgYVCgkICwIEFgIDAQIeAQIX\n' +
          'gAAKCRAFmkL4L5UZdAhiCACowW1aC8DYGtJyAaBO2MqWhyw1wVCbQN9uFsQZPydY\n' +
          'v3BEbCDrRc0HyfV1PVoRQsgkiNMes1S2tz2IMJoEOTMaz3WjPM8yK0dDbo5sfx/o\n' +
          '/XaXeKhyYNqRkz2dPzorg1sHyHe0ki/HoQiANEJ8mByMtlwnPWlhnINAX+27eL17\n' +
          'JC8juhBYUchqoIBAl+ajYKSThdLzrUkcL7QfJjZb3pPytJSTTdFc0rD6ERDbfXXc\n' +
          '/vnE2SDYme+XXn7H5tNe67tPM8M96vbp+uM+n2t/z96C+Pqb6GJFMBa35PM+/qQO\n' +
          'yr0I2oaQnTecx2AfBXGZvd81wMYikAJ9rAOWyMQZHJWouQENBFt2/VIBCADXCvKD\n' +
          '3wRWCOzRWtLTs7hpAjCDxp6niPkwxKuUf9r/sUPmn0pWdZHYlbPDev9psN9bnJ+C\n' +
          '+wzzPZ1zgSYKIAN0IMoh0L7BRAoau7VWQ3Q7hP6HIbdzOTEGyklSoh9pIh6IlwZZ\n' +
          'XfPlFlnn7FeH1UeA711E174SUpDRKYSfT+mFObQUuQewGi9QC3gBsz5MPLQQLzML\n' +
          'yimIOT+8i64fHHSKChw5ZDckBffej31/YHPQ7+JsWFV+G/6xDfbwnaFZFAUwo+1L\n' +
          '4w9UiMyCNkIWCkulzJ2Hbz66xzFMi/8zMYxr08Af+PpsXaWTQHAa5V4GNJSInDEB\n' +
          '7gy/CGLcY90EozoDABEBAAGJATwEGAEIACYWIQQVNixp3XT/DuGTF4MFmkL4L5UZ\n' +
          'dAUCW3b9UgIbDAUJA8JnAAAKCRAFmkL4L5UZdPqoB/9kpqxqa82k7JMcq7UiwQY7\n' +
          'CdqCUPKF88ciOWKBpZmpl8V7zgM7kEXwmM6ocHcznXi8xM7eOfDIJcBeqFVIE4OT\n' +
          '63OCMuvZICM9Kiu48wLNAw5W/YGAOBH7ySQzZM2XrtvwfFtJ3lR00t5f4FVtriA5\n' +
          '47BjYYG5tTdJc8HwEHs045S99xKCWqwuDgO9qskIi6iPePUkuhpaVBLuEj2Goku6\n' +
          'i8aql/vKYQS67L7UHJiEbjLe+wP9k3FvWUFTx39lAubsDzb4Abhe+qRqs2TKD7Go\n' +
          'k35ZriRIYllmx4c9KyWL7Mvzcp+84Sq9LeMfsN4JstBDJ7jn6g19SjO5dmtxSuP0\n' +
          '=zZSJ\n' +
          '-----END PGP PUBLIC KEY BLOCK-----\n'
    }
};

// (Pseudo-)Random String covering all of utf8.
function bigString (length){// eslint-disable-line no-unused-vars
    let arr = [];
    for (let i= 0; i < length; i++){
        arr.push(String.fromCharCode(
            Math.floor(Math.random() * 10174) + 1)
        );
    }
    return arr.join('');
}

function fixedLengthString (megabytes){// eslint-disable-line no-unused-vars
    let maxlength = 1024 * 1024 * megabytes / 2;
    let uint = new Uint8Array(maxlength);
    for (let i = 0; i < maxlength; i++){
        uint[i] = Math.floor(Math.random()* 256);
    }
    let td = new TextDecoder('ascii');
    let result = td.decode(uint);
    return result;
}

// (Pseudo-)Random Uint8Array, given size in Megabytes
function bigUint8 (megabytes){// eslint-disable-line no-unused-vars
    let maxlength = 1024 * 1024 * megabytes;
    let uint = new Uint8Array(maxlength);
    for (let i= 0; i < maxlength; i++){
        uint[i] = Math.floor(Math.random() * 256);
    }
    return uint;
}

// (Pseudo-)Random string with very limited charset
// (ascii only, no control chars)
function bigBoringString (megabytes){// eslint-disable-line no-unused-vars
    let maxlength = 1024 * 1024 * megabytes;
    let string = [];
    let chars =
        ' 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    for (let i= 0; i < maxlength; i++){
        string.push(chars[Math.floor(Math.random() * chars.length)]);
    }
    return string.join('');
}

// Some String with simple chars, with different characteristics, but still
// expected to occur in an averag message
// eslint-disable-next-line no-unused-vars
function slightlyLessBoringString (megabytes, set){
    let maxlength = 1024 * 1024 * megabytes;
    let string = [];
    let chars = '';
    if (set ===1 ) {
        chars = '\n"\r \'';
    } else if (set === 2 ) {
        chars = '()=?`#+-{}[]';
    } else if (set === 3){
        chars = '^°/';
    } else if (set ===4) {
        chars = 'äüßµüþÖ~ɁÑ||@';
    } else {
        chars = '*<>\n"\r§$%&/()=?`#+-{}[] \'';
    }
    for (let i= 0; i < maxlength; i++){
        string.push(chars[Math.floor(Math.random() * chars.length)]);
    }
    return string.join('');
}

// Data encrypted with testKey
const encryptedData =// eslint-disable-line no-unused-vars
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

const ImportablePublicKey = {// eslint-disable-line no-unused-vars
    fingerprint: '78034948BA7F5D0E9BDB67E4F63790C11E60278A',
    key:'-----BEGIN PGP PUBLIC KEY BLOCK-----\n' +
    '\n' +
    'mQENBFsPvK0BCACaIgoIN+3g05mrTITULK/YDTrfg4W7RdzIZBxch5CM0zdu/dby\n' +
    'esFwaJbVQIqu54CRz5xKAiWmRrQCaRvhvjY0na5r5UUIpbeQiOVrl65JtNbRmlik\n' +
    'd9Prn1kZDUOZiCPIKn+/M2ecJ92YedM7I4/BbpiaFB11cVrPFg4thepn0LB3+Whp\n' +
    '9HDm4orH9rjy6IUr6yjWNIr+LYRY6/Ip2vWcMVjleEpTFznXrm83hrJ0n0INtyox\n' +
    'Nass4eDWkgo6ItxDFFLOORSmpfrToxZymSosWqgux/qG6sxHvLqlqy6Xe3ZYRFbG\n' +
    '+JcA1oGdwOg/c0ndr6BYYiXTh8+uUJfEoZvzABEBAAG0HEJsYSBCbGEgPGJsYWJs\n' +
    'YUBleGFtcGxlLm9yZz6JAVQEEwEIAD4WIQR4A0lIun9dDpvbZ+T2N5DBHmAnigUC\n' +
    'Ww+8rQIbAwUJA8JnAAULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRD2N5DBHmAn\n' +
    'igwIB/9K3E3Yev9taZP4KnXPhk1oMQRW1MWAsFGUr+70N85VwedpUawymW4vXi1+\n' +
    'hMeTc39QjmZ0+VqHkJttkqEN6bLcEvgmU/mOlOgKdzy6eUcasYAzgoAKUqSX1SPs\n' +
    '0Imo7Tj04wnfnVwvKxaeadi0VmdqIYaW75UlrzIaltsBctyeYH8sBrvaTLscb4ON\n' +
    '46OM3Yw2G9+dBF0P+4UYFHP3EYZMlzNxfwF+i2HsYcNDHlcLfjENr9GwKn5FJqpY\n' +
    'Iq3qmI37w1hVasHDxXdz1X06dpsa6Im4ACk6LXa7xIQlXxTgPAQV0sz2yB5eY+Md\n' +
    'uzEXPGW+sq0WRp3hynn7kVP6QQYvuQENBFsPvK0BCACwvBcmbnGJk8XhEBRu2QN3\n' +
    'jKgVs3CG5nE2Xh20JipZwAuGHugDLv6/jlizzz5jtj3SAHVtJB8lJW8I0cNSEIX8\n' +
    'bRYH4C7lP2DTb9CgMcGErQIyK480+HIsbsZhJSNHdjUUl6IPEEVfSQzWaufmuswe\n' +
    'e+giqHiTsaiW20ytXilwVGpjlHBaxn/bpskZ0YRasgnPqKgJD3d5kunNqWoyCpMc\n' +
    'FYgDERvPbhhceFbvFE9G/u3gbcuV15mx53dDX0ImvPcvJnDOyJS9yr7ApdOV312p\n' +
    'A1MLbxfPnbnVu+dGXn7D/VCDd5aBYVPm+5ANrk6z9lYKH9aO5wgXpLAdJvutCOL5\n' +
    'ABEBAAGJATwEGAEIACYWIQR4A0lIun9dDpvbZ+T2N5DBHmAnigUCWw+8rQIbDAUJ\n' +
    'A8JnAAAKCRD2N5DBHmAnigMVB/484G2+3R0cAaj3V/z4gW3MRSMhcYqEMyJ/ACdo\n' +
    '7y8eoreYW843JWWVDRY6/YcYYGuBBP47WO4JuP2wIlVn17XOCSgnNjmmjsIYiAzk\n' +
    'op772TB27o0VeiFX5iWcawy0EI7JCb23xpI+QP31ksL2yyRYFXCtXSUfcOrLpCY8\n' +
    'aEQMQbAGtkag1wHTo/Tf/Vip8q0ZEQ4xOKTR2/ll6+inP8kzGyzadElUnH1Q1OUX\n' +
    'd2Lj/7BpBHE2++hAjBQRgnyaONF7mpUNEuw64iBNs0Ce6Ki4RV2+EBLnFubnFNRx\n' +
    'fFJcYXcijhuf3YCdWzqYmPpU/CtF4TgDlfSsdxHxVOmnZkY3\n' +
    '=qP6s\n' +
    '-----END PGP PUBLIC KEY BLOCK-----\n',

    keyChangedUserId: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n' +
    '\n' +
    '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\n' +
    '=9WZ7\n' +
    '-----END PGP PUBLIC KEY BLOCK-----\n'
};

/**
 * Changes base64 encoded gpg messages
 * @param {String} msg input message
 * @param {Number} rate of changes as percentage of message length.
 * @param {[Number, Number]} p begin and end of the message left untouched (to
 * preserve) header/footer
 */
// eslint-disable-next-line no-unused-vars
function sabotageMsg (msg, rate = 0.01, p= [35,35]){
    const iterations = Math.floor(Math.random() * msg.length * rate) + 1;
    const base64_set =
        'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/';
    for (let i=0; i < iterations; i++){
        let str0, str1, str2;
        const chosePosition = function (){
            let position =
                Math.floor( Math.random() * (msg.length - p[0] + p[1]))
                + p[0];
            str1 = msg.substring(position,position+1);
            if (str1 === '\n'){
                chosePosition();
            } else {
                str0 = msg.substring(0,position);
                str2 = msg.substring(position +1);
            }
        };
        chosePosition();
        let new1 = function (){
            let n = base64_set[Math.floor(Math.random() * 64)];
            return (n === str1) ? new1() : n;
        };
        msg = str0.concat(new1()).concat(str2);
    }
    return msg;
}

// a simple png
// eslint-disable-next-line no-unused-vars
const binaryData = {
    base64:
        'iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAIAAABvFaqvAAAEwElEQVQ4y62R228b1xn' +
        'E51z27I271K64okTqRkuOLRuNHcNBCqTwS//qvvYCtAmQNrETO7akyJJsipRIUeSSez' +
        'vnfH1IkBboW5F5mpf5ATPDiAi/hTh+I8n/I/NrCcbY/4DI/GKY+E/CGLIWROCccQ7Or' +
        'bVVXWmttTHKUY6UjuP8jJMggilhVjAluILwIUMwRlpTUVBVQWsoxT1PS3E7v7u6Ho0m' +
        '48boOIz63V6WdsIgZIxJmBXyMyx/QjWEbCPYReuQRNsWhbm5tqMRFQVPU6x3JlZ/e/r' +
        'm76+/OR6elbrKovT5/ae/f/L5YGcQeL5EOcHsa8z/hOY1eIbVF6b5o/YeNrnWFxf2+5' +
        'fs5kY9PDKHdlgu/vrPv/357F95UxLo7G44nk+EEO2orbKuRHOL1feo/wJ8hFEmn5dNv' +
        'JB8MRP1xYV79j68HrEss1ub15Ph8dXpoil+3lqTPZ+PXp7+8On9x51kXcLUsAtgARBR' +
        'ZfRpnn93voouxsJM5ptJsp1lfn+HwtDOpAX77/sM2bvVfFUW2hgJJ4bTQ9UH5YA1psz' +
        'zyYery69ezaihzx883BgM2GDgxFGqq92N3YvltDA1CGDwJU8j3/UYZ1rCTRE+QfMBpQ' +
        'BdgRzwAFwyKSAV1jvU38HGptvy+4J/8ej5sih+uHq31HUg+ePexvNHg27mcGch4aZY+' +
        '4wsB23Z4j1XCNeOtr0dG6Eyst3tFV47ZwpQcZQcDR6YUnfD9UWxSBL/06Peo0+67WRC' +
        'cinBBKmMnE8s98gcQjlh1Nn2sqArxiusyP1Yu8WdyUzVYhVpkiQ2/PX7W4PdQXdvP1x' +
        'Lx0x9Z8BkXVVU1rQgGjZ2VPNOy9nrxPGmjdRkUs8XuqhEAcOIrCzG1zdv3/x4fn7+2b' +
        'OngTMIPZfL0mJIsHJyfc3LUlyN5Jt37MfX4uixs96TmcO5MpxqggWKhlaNiUBE1pC2M' +
        'BaWOOPM40gY7hEq+fLVKx/olOVa07hEgjEwzhnzlYg9GXs2r21L8dgXLddGaWtwtBv1' +
        '/LgbWE9rzn2khK7FWPT7/Xy5bIVBO03U5qbc2+fdDZkkJBUDlGCh4h2fd0LpKlOw6VQ' +
        'MF+FQxwvlyziMAyXBJxbH8vjkhKw92N8peplyOcWRE7mMk6t4J1KRJ1arQsIwW1qqKs' +
        'ymwekV+wcTTKLeNt0OdRwowJEvXrxoJ+1wM8kTNncWQpVtIVLWapEbKIebmvQyv72pl' +
        '3da2VJMSzOu1RWAnG7KpjC1VOhK/lR++YcvucPIa6biw6V+zSy7J5/6uh3IlrEMpilm' +
        'N9fvXs0uT4KtnuoHvfBBg4Y46ztHbRvLleSrFpQrDw4OGqpv9Xi0qqf1R1hs6oPaVNp' +
        'oznlT1+VycXd5cvv2a6JnycaTA/93mRqAsYytp0UoRzO7mLPQlVEUNaY2dZ3RVoVnAN' +
        'ZExhpRmrJmDYyRXtDePgDQ3r63nuwEaUaKM8CtyZlN6fhEv33DuxtScAHmhIh62I+cx' +
        'BjDaye/XU3zO85E6HvK9bODo7X+nhdGYdrx/VgoF9ZCL20zqW9v6f17ayEBCCYDGTpc' +
        'Rc5aXdez5d3Hy/PT41MAh4eH+7s7ydY2Z8xRSjiOVC5jDLDkuBRFYm8fAEvSfwPxgHl' +
        'kzr8e4QAAAABJRU5ErkJggg==',
    encryptedArmored: '-----BEGIN PGP MESSAGE-----\n' +
        '\n' +
        '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\n' +
        '=AkaP\n' +
        '-----END PGP MESSAGE-----\n'
};

// eslint-disable-next-line no-unused-vars
const filename_files = [{
    name: 'Example-1234.txt',
    data: '-----BEGIN PGP MESSAGE-----\n' +
        '\n' +
        'hQEMA6B8jfIUScGEAQf/Ylt9GDcv/PGjX8v8CBWIeetzD7DpB8c5dZu57rPOhF7a\n' +
        'gZ5wUCNwuZ5jSnPh/MAH1amr9AEHhW28JlHq+Lpoohl50iNFQy01M+Kxh1LmSKup\n' +
        'hFQl3Lu+NewdShq/RwNc9+qdTAnCdwjGJ+SxODfo73cflLl9SSPJ7k29bdUUL1mp\n' +
        'aGlYdecTB6lcz4pCNOyyGryDBJQcS5ObulpN4zvhSfFzT27GQFmQPElm7CTdGOf0\n' +
        '5VUxFe0TqRmdJ9LzVuOVZB7x8E0BpuQYpPd88emS+KOozx4KWu0IakdQ4QBY0av5\n' +
        'ZID2rgM640Z4T8kXgGZq2qFN1Ap5X3iwfjkEHaJIP9JXAb86F8IP7nLrxzN2V0eM\n' +
        '3v0+1o0HJd/E4LPeXHXCaNDaJOr8rviOCLwoFvCJ9E10ZASLyqOXzhlW9Tkvxrjl\n' +
        'ldeXQI8Fp6oWPfvW8qGQ917mzxuoQYGn\n' +
        '=993W\n' +
        '-----END PGP MESSAGE-----\n'
}, {
    name: 'Example-@€µ2äüß.txt',
    data: '-----BEGIN PGP MESSAGE-----\n'+
        '\n'+
        'hQEMA6B8jfIUScGEAQgAiX5vBNJGPYvljleo/7nkee4mGsFL1ROXLOs7sUlBImFm\n'+
        'axQ0PAtVsX9NvDY70Tj5EIaGmgQWr/WAnH5fuV+ctsZtPm/UsL2BhYgKz3cDcS2P\n'+
        '1tni3WhHXVr8ldC3PePuEn0Wfy/wOS+y2FbkJOD9EqXeui06phB8ScGdF6se3AcA\n'+
        'lNo6bFeURgK6NhIYgibKbybAr1+D/zUvksn5xnLztBarVeJFOwAj8I+lthLpoyj2\n'+
        'vUFu2qOlSOW/98Z0ZYDvRqnB5Mqmqsgf0cWl4Lwt0+GrdfzuB+479+ouIJCFUaIA\n'+
        'JDoU8Ct0UwgAoYZmDkxBtjZALmf3dGqH1gjSe0UbDdJhAZ9h5rlC525JNOse0v21\n'+
        'LdrDtwtiETFZ9ras8RelYeyYyE7PfhBxtmP5EBZUk7Be6JbD2vn5s2pgsbmBTzGJ\n'+
        'AcxxSN6MbTvInIvC3GhSTs0mLiC4sToVoPp/F8tfQIGZWg==\n'+
        '=V6wP\n'+
        '-----END PGP MESSAGE-----\n'
}, {
    name: 'Example- äüüß.txt',
    data: '-----BEGIN PGP MESSAGE-----\n' +
        '\n' +
        'hQEMA6B8jfIUScGEAQf9H7CbkI952WbUqkuYIlgKri+Tr+G+9m1GN/mKh82GnwfZ\n' +
        '8JekOOzdZ6BdCfyJohOSan959r1pOHJzj2sh+LitBbD02MDPg8BL14lUXfbUju7s\n' +
        'eT5HuVDfnFWV2ThfEyVUNmAEaE57FwTzdO7vN1VYkkBNFC8pjCONQ6/iRWnDgUyB\n' +
        'fJJSLkdFMDBgHSrEeSCyDP4P5rJyd/1JhqXXECLIMzIKWCUbvWNvKLfA71fhPbi3\n' +
        'XzXLWhNKQWoMZsl2oEHJuPY7ez/KePJ07Km0gxcbBJhUGTRRNrHSjOxiaV7/TLp2\n' +
        'O3U/GuPQ/eY4Xl3rE/cDaCjy2sdR4VyuxlbLeUVIvtJbAUzNkaibs9ydZshBj9UD\n' +
        'x2JWCwkBa7Q1Mah9nciT8S2Co71dsVMdIc3VtsXUtlhomL1bHd8ipRhFSiqiyZM3\n' +
        'Pih6tFUOcXuSaf0lv6FENXP+IThHiaujtjAbkA==\n' +
        '=UxvV\n' +
        '-----END PGP MESSAGE-----\n'
}];
