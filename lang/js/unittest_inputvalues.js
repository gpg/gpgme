import { createKey } from './src/Key';

export const helper_params = {
    validLongId: '0A0A0A0A0A0A0A0A',
    validKeys: ['A1E3BC45BDC8E87B74F4392D53B151A1368E50F3',
        createKey('D41735B91236FDB882048C5A2301635EEFF0CB05'),
        'EE17AEE730F88F1DE7713C54BBE0A4FF7851650A'],
    validFingerprint: '9A9A7A7A8A9A9A7A7A8A9A9A7A7A8A9A9A7A7A8A',
    validFingerprints: ['9A9A7A7A8A9A9A7A7A8A9A9A7A7A8A9A9A7A7A8A',
        '9AAE7A338A9A9A7A7A8A9A9A7A7A8A9A9A7A7DDA'],
    invalidLongId: '9A9A7A7A8A9A9A7A7A8A',
    invalidFingerprints: [{ hello:'World' }, ['kekekeke'], new Uint32Array(40)],
    invalidKeyArray: { curiosity:'uncat' },
    invalidKeyArray_OneBad: [
        createKey('D41735B91236FDB882048C5A2301635EEFF0CB05'),
        'E1D18E6E994FA9FE9360Bx0E687B940FEFEB095A',
        '3AEA7FE4F5F416ED18CEC63DD519450D9C0FAEE5'],
    invalidErrorCode: 'Please type in all your passwords.',
    validGPGME_Key: createKey('D41735B91236FDB882048C5A2301635EEFF0CB05', true),
    valid_openpgplike: { primaryKey: {
        getFingerprint: function (){
            return '85DE2A8BA5A5AB3A8A7BE2000B8AED24D7534BC2';}
    }
    }
};

export const message_params = {
    invalid_op_action : 'dance',
    invalid_op_type : [234, 34, '<>'],
    valid_encrypt_data: 'مرحبا بالعالم',
    invalid_param_test: {
        valid_op: 'encrypt',
        invalid_param_names: [22,'dance', {}],
        validparam_name_0: 'mime',
        invalid_values_0: [2134, 'All your passwords',
            createKey('12AE9F3E41B33BF77DF52B6BE8EE1992D7909B08'), null]
    }
};

export const whatever_params = {
    four_invalid_params: ['<(((-<', '>°;==;~~', '^^', '{{{{o}}}}'],
};
export const key_params = {
// A Key you own (= having a secret Key) in GPG. See testkey.pub/testkey.sec
    validKeyFingerprint: 'D41735B91236FDB882048C5A2301635EEFF0CB05',
    // A Key you do not own (= having no secret Key) in GPG. See testkey2.pub
    validFingerprintNoSecret: 'E059A1E0866D31AE131170884D9A2E13304153D1',
    // A Key not in your Keyring. This is just a random hex string.
    invalidKeyFingerprint: 'CDC3A2B2860625CCBFC5AAAAAC6D1B604967FC4A',
    validKeyProperties: ['expired', 'disabled','invalid','can_encrypt',
        'can_sign','can_certify','can_authenticate','secret','is_qualified']
};
export const armoredKey = {
    fingerprint: '78034948BA7F5D0E9BDB67E4F63790C11E60278A',
    key:'-----BEGIN PGP PUBLIC KEY BLOCK-----\n' +
        '\n' +
        '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\n' +
        '=qP6s\n' +
        '-----END PGP PUBLIC KEY BLOCK-----\n',
    keyChangedUserId: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n' +
        '\n' +
        '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\n' +
        '=9WZ7\n' +
        '-----END PGP PUBLIC KEY BLOCK-----\n'
};