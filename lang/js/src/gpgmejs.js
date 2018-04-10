import {Connection} from "./Connection"

export function encrypt(data, publicKeys, privateKeys, passwords=null,
    sessionKey, filename, compression, armor=true, detached=false,
    signature=null, returnSessionKey=false, wildcard=false, date=new Date()){
        // gpgme_op_encrypt ( <-gpgme doc on this operation
            // gpgme_ctx_t ctx,
            // gpgme_key_t recp[],
            // gpgme_encrypt_flags_t flags,
            // gpgme_data_t plain,
            // gpgme_data_t cipher)
            // flags:
            // GPGME_ENCRYPT_ALWAYS_TRUST
            // GPGME_ENCRYPT_NO_ENCRYPT_TO
            // GPGME_ENCRYPT_NO_COMPRESS
            // GPGME_ENCRYPT_PREPARE
            // GPGME_ENCRYPT_EXPECT_SIGN
            // GPGME_ENCRYPT_SYMMETRIC
            // GPGME_ENCRYPT_THROW_KEYIDS
            // GPGME_ENCRYPT_WRAP
    if (passwords !== null){
        throw('Password!'); // TBD
    }

    let pubkeys = toKeyIdArray(publicKeys);
    let privkeys = toKeyIdArray(privateKeys);

    // TODO filename: data is supposed to be empty, file is provided
    // TODO config compression detached signature
    // TODO signature to add to the encrypted message (?) ||  privateKeys: signature is desired
    //  gpgme_op_encrypt_sign (gpgme_ctx_t ctx, gpgme_key_t recp[], gpgme_encrypt_flags_t flags, gpgme_data_t plain, gpgme_data_t cipher)

    // TODO sign date overwriting implemented in gnupg?

    let conn = new Connection();
    if (wildcard){
        // Connection.set('throw-keyids', true); TODO Connection.set not yet existant
    }
    return conn.post('encrypt', {
        'data': data,
        'keys': publicKeys,
        'armor': armor});
};

export function decrypt(message, privateKeys, passwords, sessionKeys, publicKeys,
    format='utf8', signature=null, date=new Date()) {
    if (passwords !== null){
        throw('Password!'); // TBD
    }
    if (format === 'binary'){
        // Connection.set('base64', true);
    }
    if (publicKeys || signature){
        // Connection.set('signature', signature);
        // request verification, too
    }
    //privateKeys optionally if keyId was thrown?
    // gpgme_op_decrypt (gpgme_ctx_t ctx, gpgme_data_t cipher, gpgme_data_t plain)
    // response is gpgme_op_decrypt_result (gpgme_ctx_t ctx) (next available?)
    return conn.post('decrypt', {
        'data': message
    });
}

// BIG TODO.
export function generateKey({userIds=[], passphrase, numBits=2048, unlocked=false, keyExpirationTime=0, curve="", date=new Date()}){
    throw('not implemented here');
        // gpgme_op_createkey (gpgme_ctx_t ctx, const char *userid, const char *algo, unsigned long reserved, unsigned long expires, gpgme_key_t extrakey, unsigned int flags);
    return false;
}

export function sign({ data, privateKeys, armor=true, detached=false, date=new Date() }) {
    //TODO detached GPGME_SIG_MODE_DETACH | GPGME_SIG_MODE_NORMAL
    // gpgme_op_sign (gpgme_ctx_t ctx, gpgme_data_t plain, gpgme_data_t sig, gpgme_sig_mode_t mode)
    // TODO date not supported

    let conn = new Connection();
    let privkeys = toKeyIdArray(privateKeys);
    return conn.post('sign', {
        'data': data,
        'keys': privkeys,
        'armor': armor});
};

export function verify({ message, publicKeys, signature=null, date=new Date() }) {
    //TODO extra signature: sig, signed_text, plain: null
    // inline sig: signed_text:null, plain as writable (?)
    // date not supported
    //gpgme_op_verify (gpgme_ctx_t ctx, gpgme_data_t sig, gpgme_data_t signed_text, gpgme_data_t plain)
    let conn = new Connection();
    let privkeys = toKeyIdArray(privateKeys);
    return conn.post('sign', {
        'data': data,
        'keys': privkeys,
        'armor': armor});
}


export function reformatKey(privateKey, userIds=[], passphrase="", unlocked=false, keyExpirationTime=0){
    let privKey = toKeyIdArray(privateKey);
    if (privKey.length !== 1){
        return false; //TODO some error handling. There is not exactly ONE key we are editing
    }
    let conn = new Connection();
    // TODO key management needs to be changed somewhat
    return conn.post('TODO', {
        'key': privKey[0],
        'keyExpirationTime': keyExpirationTime, //TODO check if this is 0 or a positive and plausible number
        'userIds': userIds //TODO check if empty or plausible strings
    });
    // unlocked will be ignored
}

export function decryptKey({ privateKey, passphrase }) {
    throw('not implemented here');
    return false;
};

export function encryptKey({ privateKey, passphrase }) {
    throw('not implemented here');
    return false;
};

export function encryptSessionKey({data, algorithm, publicKeys, passwords, wildcard=false }) {
    //openpgpjs:
    // Encrypt a symmetric session key with public keys, passwords, or both at
    // once. At least either public keys or passwords must be specified.
    throw('not implemented here');
    return false;
};

export function decryptSessionKeys({ message, privateKeys, passwords }) {
    throw('not implemented here');
    return false;
};

// //TODO worker handling

// //TODO key representation
// //TODO: keyring handling


/**
 * Helper functions and checks
 */

/**
 * Checks if the submitted value is a keyID.
 * TODO: should accept all strings that are accepted as keyID by gnupg
 * TODO: See if Key becomes an object later on
 * @param {*} key input value. Is expected to be a string of 8,16 or 40 chars
 * representing hex values. Will return false if that expectation is not met
 */
function isKeyId(key){
    if (!key || typeof(key) !== "string"){
        return false;
    }
    if ([8,16,40].indexOf(key.length) < 0){
        return false;
    }
    let regexp= /^[0-9a-fA-F]*$/i;
    return regexp.test(key);
};

/**
 * Tries to return an array of keyID values, either from a string or an array.
 * Filters out those that do not meet the criteria. (TODO: silently for now)
 * @param {*} array Input value.
 */
function toKeyIdArray(array){
    let result = [];
    if (!array){
        return result;
    }
    if (!Array.isArray(array)){
        if (isKeyId(array) === true){
            return [keyId];
        }
        return result;
    }
    for (let i=0; i < array.length; i++){
        if (isKeyId(array[i]) === true){
            result.push(array[i]);
        }
    }
    return result;
};
