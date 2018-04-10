/**
 * A connection port will be opened for each communication between gpgmejs and
 * gnupg. It should be alive as long as there are additional messages to be
 * expected.
 */

export function Connection(){
    if (!this.connection){
        this.connection = connect();
        this._msg = {
            'always-trust': true,
            // 'no-encrypt-to': false,
            // 'no-compress': true,
            // 'throw-keyids': false,
            // 'wrap': false,
            'armor': true,
            'base64': false
        };
    };

    this.disconnect = function () {
        if (this.connection){
            this.connection.disconnect();
        }
    };

    /**
     * Sends a message and resolves with the answer.
     * @param {*} operation The interaction requested from gpgme
     * @param {*} message A json-capable object to pass the operation details.
     * TODO: _msg should contain configurable parameters
     */
    this.post = function(operation, message){
        let timeout = 5000;
        let me = this;
        if (!message || !operation){
            return Promise.reject('no message'); // TBD
        }

        let keys = Object.keys(message);
        for (let i=0; i < keys.length; i++){
            let property = keys[i];
            me._msg[property] = message[property];
        }
        me._msg['op'] = operation;
        // TODO fancier checks if what we want is consistent with submitted content
        return new Promise(function(resolve, reject){
            me.connection.onMessage.addListener(function(msg) {
                if (!msg){
                    reject('empty answer.');
                }
                if (msg.type === "error"){
                    reject(msg.msg);
                }
                    resolve(msg);
            });

            me.connection.postMessage(me._msg);
            setTimeout(
                function(){
                    me.disconnect();
                    reject('Timeout');
                }, timeout);
        });
     };
};


function connect(){
    let connection = chrome.runtime.connectNative('gpgmejson');
    if (!connection){
        let msg = chrome.runtime.lastError || 'no message'; //TBD
        throw(msg);
    }
    return connection;
};
