// configuration values for the client to operate
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
function GriffinSecret() {

}

// wrapper object to contain signing keys, encryption keys, and all the encrypted
// secrets that we can pickle and store to the filesystem
function GriffinKeySet() {
    this.KEY_DB_NAME = "griffin.kdb";
    this.BASE_32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    this.version = 1;
    this.ED25519_PRIVATE_KEY = null;
    this.ED25519_VERIFY_KEY = null;
    this.SALSA20_PRIVATE_KEY = null;
    // email address of user
    this.email = null;
    // dict of secrets: obviously not ACID compliant, but this is a
    // reference client, not intended for multi-threaded use
    this.secrets = {};
    // storage object for session related data
    this.session = {
        active: false,
        username: null,
        masterPassphrase: null
    };
}

GriffinKeySet.prototype = {
    /* generate sigining and encryption keys, store them in localStorage
     *
     * args: string email address of user
     */
    generateKeys: function(email) {
        // generate new signing key
        var keypair = sodium.crypto_sign_keypair();
        // generate the new symmetric encryption key
        var encrypt_key = sodium.randombytes_buf(sodium.crypto_box_SECRETKEYBYTES);
        // encode and store our keys
        this.ED25519_PRIVATE_KEY = Utils.bytesToB64(keypair.privateKey);
        this.ED25519_VERIFY_KEY = Utils.bytesToB64(keypair.publicKey);
        this.SALSA20_PRIVATE_KEY = Utils.bytesToB64(encrypt_key);
        // store the email address (username)
        this.email = email;
        // persist keys to localStorage
        this.storeKeys();
    },

    storeKeys: function() {
        var passphrase = this.session.masterPassphrase;
        // generate random salt
        var salt = sodium.randombytes_buf(sodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
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
        window.localStorage.setItem(this.KEY_DB_NAME, serialized);
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

    // TODO decryption failure should return an error code that the client can consume
    loadKeys: function() {
        // get encrypted keys from localStorage
        var encrypted = JSON.parse(window.localStorage.getItem(this.KEY_DB_NAME));
        // fetch master passphrase from DOM or prompt user
        var passphrase = this.session.masterPassphrase;
        // extract salt from serialized object
        var salt = Utils.b64ToBytes(encrypted.salt);
        // derive decryption key from master passphrase
        var key = this.deriveMasterKey(passphrase, salt);

        // decrypt and parse key set
        var encryptedKeys = EncryptedMessage.fromB64Obj(encrypted.keyset)
        var keys = JSON.parse(Utils.bytesToString(this.decryptMsg(encryptedKeys, key)));

        // read the decrypted keys and properties into our object
        this.ED25519_PRIVATE_KEY = keys.ED25519_PRIVATE_KEY;
        this.ED25519_VERIFY_KEY = keys.ED25519_VERIFY_KEY;
        this.SALSA20_PRIVATE_KEY = keys.SALSA20_PRIVATE_KEY;
        this.secrets = keys.secrets;
        this.email = keys.email;
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
    }
};
