import {Connection} from "./src/Connection";
import {createKey} from "./src/Key";

let conn = new Connection;

export const helper_params = {
    validLongId: '0A0A0A0A0A0A0A0A',
    validKeys: ['A1E3BC45BDC8E87B74F4392D53B151A1368E50F3',
        createKey('ADDBC303B6D31026F5EB4591A27EABDF283121BB', conn),
        'EE17AEE730F88F1DE7713C54BBE0A4FF7851650A'],
    validFingerprint: '9A9A7A7A8A9A9A7A7A8A9A9A7A7A8A9A9A7A7A8A',
    validFingerprints: ['9A9A7A7A8A9A9A7A7A8A9A9A7A7A8A9A9A7A7A8A',
        '9AAE7A338A9A9A7A7A8A9A9A7A7A8A9A9A7A7DDA'],
    invalidLongId: '9A9A7A7A8A9A9A7A7A8A',
    invalidFingerprints: [{hello:'World'}, ['kekekeke'], new Uint32Array(40)],
    invalidKeyArray: {curiosity:'uncat'},
    invalidKeyArray_OneBad: [
        createKey('12AE9F3E41B33BF77DF52B6BE8EE1992D7909B08', conn),
        'E1D18E6E994FA9FE9360Bx0E687B940FEFEB095A',
        '3AEA7FE4F5F416ED18CEC63DD519450D9C0FAEE5'],
    invalidErrorCode: 'Please type in all your passwords.',
    validGPGME_Key: createKey('ADDBC303B6D31026F5EB4591A27EABDF283121BB', conn),
    valid_openpgplike: { primaryKey: {
        getFingerprint: function(){
            return '85DE2A8BA5A5AB3A8A7BE2000B8AED24D7534BC2';}
        }
    }
}

export const message_params = {
    invalid_op_action : 'dance',
    invalid_op_type : [234, 34, '<>'],
    valid_encrypt_data: "مرحبا بالعالم",
    invalid_param_test: {
        valid_op: 'encrypt',
        invalid_param_names: [22,'dance', {}],
        validparam_name_0: 'mime',
        invalid_values_0: [2134, 'All your passwords',
            createKey('12AE9F3E41B33BF77DF52B6BE8EE1992D7909B08', conn), null]
    }
}

export const whatever_params = {
    four_invalid_params: ['<(((-<', '>°;==;~~', '^^', '{{{{o}}}}']
}
