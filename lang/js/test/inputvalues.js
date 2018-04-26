
import {GPGME_Key} from "../src/Key"

export const helper_params = {
    validLongId: '0A0A0A0A0A0A0A0A',
    validGPGME_Key: new GPGME_Key('ADDBC303B6D31026F5EB4591A27EABDF283121BB'),
    validKeys: [new GPGME_Key('A1E3BC45BDC8E87B74F4392D53B151A1368E50F3'),
        'ADDBC303B6D31026F5EB4591A27EABDF283121BB',
        new GPGME_Key('EE17AEE730F88F1DE7713C54BBE0A4FF7851650A')],
    validFingerprint: '9A9A7A7A8A9A9A7A7A8A9A9A7A7A8A9A9A7A7A8A',
    invalidLongId: '9A9A7A7A8A9A9A7A7A8A',
    invalidFingerprint: [{hello:'World'}],
    invalidKeyArray: {curiosity:'uncat'},
    invalidKeyArray_OneBad: [
        new GPGME_Key('12AE9F3E41B33BF77DF52B6BE8EE1992D7909B08'),
        'E1D18E6E994FA9FE9360Bx0E687B940FEFEB095A',
        '3AEA7FE4F5F416ED18CEC63DD519450D9C0FAEE5'],
    invalidErrorCode: 'Please type in all your passwords.'
}

export const message_params = {
    invalid_op_action : 'dance',
    invalid_op_type : [234, 34, '<>'],
}

export default {
    helper_params: helper_params,
    message_params: message_params
}