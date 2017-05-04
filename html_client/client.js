// TODO document everything as JSDoc:
// https://github.com/jsdoc3/jsdoc

// configuration values for the client to operate
// TODO move these to localStorage
var HTTP_SCHEME = "http";
var GRIFFIN_HOST = "griffin.local";
var GRIFFIN_PATH = "griffin";

var Utils = {
    bytesToB64: function(bytes) {
        return btoa(String.fromCharCode.apply(null, bytes));
    },

    b64ToBytes: function(b64) {
        return new Uint8Array(atob(b64).split("").map(function(c) {
	        return c.charCodeAt(0);
        }));
    },

    bytesToString: function(bytes) {
        return String.fromCharCode.apply(null, bytes);
    }
};

function EncryptedMessage(nonce, ciphertext) {
    this.nonce = Utils.bytesToB64(nonce);
    this.ciphertext = Utils.bytesToB64(ciphertext);
}

EncryptedMessage.fromB64Obj = function(obj) {
    return new EncryptedMessage(Utils.b64ToBytes(obj.nonce),
                                Utils.b64ToBytes(obj.ciphertext));
};

EncryptedMessage.prototype = {
    getNonce: function() {
        return Utils.b64ToBytes(this.nonce);
    },

    getCiphertext: function() {
        return Utils.b64ToBytes(this.ciphertext);
    }
};

// TODO keep track of secret age so we can prompt for password rotation
function GriffinSecret(data) {
    this.id = null;
    // last updated time (ms since epoch)
    this.updated = null;
    // schema version for stored secrets
    this.schema = 1;
    // secret attributes to store
    this.data = data;
}
GriffinSecret.prototype = {
    /* update the last updated timestamp
     *
     * args: Number timestamp milliseconds since epoch
     */
    touch: function(timestamp) {
        timestamp = timestamp || new Date().getTime();
        this.updated = timestamp;
    }
};

// wrapper object to contain signing keys, encryption keys, and all the
// encrypted secrets that we can pickle and store to the filesystem
function GriffinKeySet() {
    this.BASE_32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    this.LOWER = "abcdefghijklmnopqrstuvwxyz";
    this.UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    this.NUMBERS = "0123456789";
    this.SPECIAL = "!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~";

    //this.version = 2;
    this.ED25519_PRIVATE_KEY = null;
    this.ED25519_VERIFY_KEY = null;
    this.SALSA20_PRIVATE_KEY = null;
    // email address of user
    this.email = null;
    // default configuration settings
    this.config = {
        "generate-length": 12,
        "generate-numbers": true,
        "generate-lower": true,
        "generate-upper": true,
        "generate-special":true,
        "generate-exclude-similar": true
    };
    this.secrets = {};
    // storage object for session related data
    this.session = {
        active: false,
        username: null,
        masterPassphrase: null
    };
}

GriffinKeySet.prototype = {
    /* return a key to use in localStorage based on a hashed username
     *
     * returns: string keyDB name
     */
    getKeyDBName: function() {
        var userHash = Utils.bytesToB64(
            sodium.crypto_hash(this.session.username).slice(0, 12)
        );
        return "griffin." + userHash + ".kdb";
    },
        
    /* generate sigining and encryption keys, store them in localStorage
     *
     * args: string email address of user
     */
    generateKeys: function(email) {
        // generate new signing key
        var keypair = sodium.crypto_sign_keypair();
        // generate the new symmetric encryption key
        var encrypt_key = sodium.randombytes_buf(
            sodium.crypto_box_SECRETKEYBYTES
        );
        // encode and store our keys
        this.ED25519_PRIVATE_KEY = Utils.bytesToB64(keypair.privateKey);
        this.ED25519_VERIFY_KEY = Utils.bytesToB64(keypair.publicKey);
        this.SALSA20_PRIVATE_KEY = Utils.bytesToB64(encrypt_key);
        // store the email address (username)
        this.email = email;
        // persist keys to localStorage
        this.storeKeys();
    },

    /* generate secure password
     *
     * returns: string password
     */
    generatePassword: function() {
        var password = "";
        var charset = "";
        var charmap = {
            "generate-lower": this.LOWER,
            "generate-upper": this.UPPER,
            "generate-numbers": this.NUMBERS,
            "generate-special": this.SPECIAL
        }
        // determine character set based on config options
        for (prop in charmap) {
            if (this.config[prop] === true) {
                charset += charmap[prop];
            }
        }
        // remove visually similar characters if configured
        if (this.config["generate-exclude-similar"] === true) {
            charset.replace(/B8G6I1l0OQDS5Z2/g, "");
        }
        // generate password based on random selection from character set
        while (password.length < this.config["generate-length"]) {
            var i = sodium.randombytes_uniform(charset.length);
            password += charset[i];
        }
        return password;
    },

    /* encrypt, serialize, and store the keyset and configuration settings
     * to localStorage
     */
    storeKeys: function() {
        var passphrase = this.session.masterPassphrase;
        // generate random salt
        var salt = sodium.randombytes_buf(
            sodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES
        );
        // derive master encryption key
        var masterKey = this.deriveMasterKey(passphrase, salt);
        // encapsulate the salt and encrypted key set
        var encrypted = {
            salt: Utils.bytesToB64(salt),
            keyset: this.encryptMsg(JSON.stringify(this), masterKey)
        };
        // serialize the encrypted keys for localStorage
        var serialized = JSON.stringify(encrypted);
        // persist encrypted keys in localStorage
        window.localStorage.setItem(this.getKeyDBName(), serialized);
    },

    deriveMasterKey: function(passphrase, salt) {
        return sodium.crypto_pwhash_scryptsalsa208sha256(
            passphrase,
            salt,
            sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
            sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE,
            sodium.crypto_box_SEEDBYTES
        );
    },

    /* read encrypted keys from localStorage, decrypt them, populate the keyset
    */
    loadKeys: function() {
        try {
            // get encrypted keys from localStorage
            var encrypted = JSON.parse(
                window.localStorage.getItem(this.getKeyDBName())
            );
            // fetch master passphrase from DOM or prompt user
            var passphrase = this.session.masterPassphrase;
            // extract salt from serialized object
            var salt = Utils.b64ToBytes(encrypted.salt);
            // derive decryption key from master passphrase
            var key = this.deriveMasterKey(passphrase, salt);

            // decrypt and parse key set
            var encryptedKeys = EncryptedMessage.fromB64Obj(encrypted.keyset);
            var keys = JSON.parse(Utils.bytesToString(
                this.decryptMsg(encryptedKeys, key))
            );

            // perform any necessary data conversions to make key version
            // match the client version
            while (keys.version < this.version) {
                this.doConversion(keys);
            }
            
            // read the decrypted keys and properties into our object
            this.ED25519_PRIVATE_KEY = keys.ED25519_PRIVATE_KEY;
            this.ED25519_VERIFY_KEY = keys.ED25519_VERIFY_KEY;
            this.SALSA20_PRIVATE_KEY = keys.SALSA20_PRIVATE_KEY;
            this.config = keys.config;
            this.secrets = keys.secrets;
            this.email = keys.email;

            // indicate success to caller
            return true;
        }
        catch (e) {
            return false
        }
    },

    doConversion: function(keys) {
    },

    /* return the byte array for our symmetric encryption key
     *
     * returns: Uint8Array key bytes
     */
    getEncryptKey: function() {
        if (this.SALSA20_PRIVATE_KEY === null)
            return null;
        return Utils.b64ToBytes(this.SALSA20_PRIVATE_KEY);
    },

    /* encrypt a message using the symmetric private key
     *
     * args: string msg, (optional) Uint8Array key bytes
     * returns: EncryptedMessage
     */
    encryptMsg: function(msg, key) {
        // use the passed-in encryption key, otherwise use our internal key
        var key = key || this.getEncryptKey();
        var nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
        var ciphertext = sodium.crypto_secretbox_easy(msg, nonce, key);
        return new EncryptedMessage(nonce, ciphertext);
    },

    /* decrypt an EncryptedMessage and return the plaintext
     * 
     * args: EncryptedMessage encrypted, (optional) Uint8Array key bytes
     * returns: Uint8Array plaintext bytes
     */
    decryptMsg: function(encrypted, key) {
        // use the passed-in encryption key, otherwise use our internal key
        var key = key || this.getEncryptKey();
        return sodium.crypto_secretbox_open_easy(encrypted.getCiphertext(),
                                                 encrypted.getNonce(),
                                                 key);
    },

    /* retrieve a secret by ID
     *
     * args: number id
     * returns: GriffinSecret, null if not found
     */
    getSecret: function(id) {
        if (!this.secrets.hasOwnProperty(id)) {
            return null;
        }
        return this.secrets[id];
    },

    /* retrieve set of secrets matching search criteria
     *
     * args: object kwargs
     * returns: Array of GriffinSecrets
     */
    getSecrets: function(kwargs) {
        // sort array of secrets based on value of passed property
        sortSecrets = function(prop1, prop2) {
            return function(a, b) {
                if (a.data[prop1] < b.data[prop1])
                    return -1;
                if (a.data[prop1] > b.data[prop1])
                    return 1;
                // secondary property to sort by
                if (prop2) {
                    if (a.data[prop2] < b.data[prop2])
                        return -1;
                    if (a.data[prop2] > b.data[prop2])
                        return 1;
                }
                return 0
            }
        };
        var secrets = [];
        for (var i in this.secrets) {
            // filter out deleted secrets
            if (jQuery.isEmptyObject(this.secrets[i].data)) {
                continue;
            }
            // try to match query terms
            if (kwargs !== undefined) {
                if ((this.secrets[i].data.site.toLowerCase().includes(kwargs)) ||
                    (this.secrets[i].data.username.toLowerCase().includes(kwargs))) {
                    secrets.push(this.secrets[i]);
                }
            }
            // no query so include everything
            else {
                secrets.push(this.secrets[i]);
            }
        }
        secrets.sort(sortSecrets("site", "username"));
        return secrets;
    },

    /* save a secret into the local keyset
     *
     * args: GriffinSecret
     */
    saveSecret: function(secret) {
        // no ID specified, generate a new secret ID
        if (secret.id == null) {
            secret.id = this.getNextId();
        }
        // ID specified, determine if we need to update existing record or skip
        // the update if the local copy is newer
        else {
            var existing = this.getSecret(secret.id);
            if ((existing != null) && (existing.updated > secret.updated)) {
                return;
            }
        }
        // secret passed in is new or newer than our existing copy, so store it
        this.secrets[secret.id] = secret;
        this.storeKeys();
    },

    /* Delete a secret from the keyset. In practice, this means overwriting the
     * secret data with an empty object so we don't re-use the ID.
     * 
     * args: number id
     */
    deleteSecret: function(id) {
        var secret = this.getSecret(id);
        secret.data = {}
        this.saveSecret(secret);
        this.storeKeys();
    },

    /* return the next highest integer for use as a secret ID
     *
     * returns: Number
     */
    getNextId: function() {
        if (jQuery.isEmptyObject(this.secrets)) {
            return 0;
        }
        return parseInt(Math.max.apply(null, Object.keys(griffin.secrets))) + 1;
    }
};
