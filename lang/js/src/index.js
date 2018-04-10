import * as gpgmejs from'./gpgmejs'
export default gpgmejs;

/**
 * Export each high level api function separately.
 * Usage:
 *
 *   import { encryptMessage } from 'gpgme.js'
 *   encryptMessage(keys, text)
 */
export {
    encrypt, decrypt, sign, verify,
    generateKey, reformatKey
  } from './gpgmejs';
