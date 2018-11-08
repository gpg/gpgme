Using gpgme.js
---------------
At first, make sure that the environment you want to use gpgme.js in has access
and permissions for nativeMessaging, and gpgme-json installed. For details,
see the README.

The library itself is started via the {@link init} method. This will test the
nativeMessaging connection, and then resolve into an Object offering
the top level API:

* [encrypt]{@link GpgME#encrypt}
* [decrypt]{@link GpgME#decrypt}
* [sign]{@link GpgME#sign}
* [verify]{@link GpgME#verify}
* [Keyring]{@link GPGME_Keyring}

```
gpgmejs.init()
    .then(function(GPGME) {
        // using GPGME
    }, function(error){
        // error handling;
    })
```

All methods that require communication with nativeMessaging are asynchronous,
using Promises. Rejections will be instances of {@link GPGME_Error}.

An exaeption are Keys, which can be initialized in a 'sync' mode, allowing them
to be cached and used synchronously until manually refreshed.

Keyring and Keys
----------------
The gnupg keys can be accessed via the [Keyring]{@link GPGME_Keyring}.

The Keyring offers the methods for accessing information on all Keys known to
gnupg.

**Due to security constraints, the javascript-binding currently only offers
limited support for secret-Key interaction.**

The existence of secret Keys is not secret, and those secret Keys can be used
for signing, but Operations that may expose, modify or delete secret Keys are
not supported.

* [getKeysArmored]{@link GPGME_Keyring#getKeysArmored}
* [getKeys]{@link GPGME_Keyring#getKeys}
* [getDefaultKey]{@link GPGME_Keyring#getDefaultKey}
* [generateKey]{@link GPGME_Keyring#generateKey}
* [deleteKey]{@link GPGME_Keyring#deleteKey}
