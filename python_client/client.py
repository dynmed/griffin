# Python reference client for Griffin Password Manager
import nacl.encoding
import nacl.signing
import nacl.secret
import nacl.utils
import nacl.hash
import argparse
import os
import sys
import urllib2
import urlparse
import datetime
import base64
import json
import textwrap
import pickle

# configuration values for the client to operate
HTTP_SCHEME = "http"
GRIFFIN_HOST = "griffin.local"
GRIFFIN_PATH = "griffin"

# Parse a list of command line arguments and return a data structure containing
# the configuration options
def parse_args(args = None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--generate-keyset", dest="generate_keyset",
                        action="store_true",
                        help="Generate a new set of signing and encryption keys")
    parser.add_argument("--register-user", dest="register_user", action="store_true",
                        help="Register a new user on the server")
    parser.add_argument("--key-location", dest="key_location", action="store",
                        help="Directory to store the keys in")
    parser.add_argument("--create-record", dest="create_record", action="store_true",
                        help="Create a Griffin record on the server")
    parser.add_argument("--send-secrets", dest="send_secrets", action="store_true",
                        help="Send Griffin secrets for storage on the server")
    parser.add_argument("--age", dest="age", action="store",
                        help="Secret record age (in seconds) to process")
    parser.add_argument("--metadata", dest="metadata", action="store",
                        help="Create a Griffin record with the following metadata")
    parser.add_argument("--data", dest="data", action="store",
                        help="Create a Griffin record with the following data")
    parser.add_argument("--email", dest="email", action="store",
                        help="Email address to use for the transaction")
    parser.add_argument("--get-record", dest="get_record", action="store",
                        help="Get a Griffin record from the server")
    parser.add_argument("--http-debug", dest="http_debug", action="store_true",
                        help="Print verbose HTTP requests and responses")
    args = parser.parse_args()
    # validate the arg combinations, etc.
    if args.generate_keyset:
        if args.key_location is None:
            parser.error("--generate-keyset requires --key-location also be specified")
        if args.email is None:
            parser.error("--generate-keyset requires --email also be specified")
    if args.create_record:
        if args.key_location is None:
            parser.error("--create-record requires --key-location also be specified")
        if args.metadata is None:
            parser.error("--create-record requires --metadata also be specified")
        if args.data is None:
            parser.error("--create-record requires --data also be specified")
    if args.send_secrets:
        if args.key_location is None:
            parser.error("--send-secrets requires --key-location also be specified")
        if args.age is None:
            parser.error("--send-secrets requires --age also be specified")
    if args.get_record is not None and args.key_location is None:
        parser.error("--get-record requires --key-location also be specified")
    if args.register_user:
        if args.key_location is None:
            parser.error("--register-user requires --key-location also be specified")
    return args

# Create and return a URL-fetching object
#
# args: int debuglevel (1 for verbose HTTP output)
# returns: urllib2.OpenerDirector
def build_http_opener(debuglevel = 0):
    http = urllib2.HTTPHandler(debuglevel)
    return urllib2.build_opener(http)

# URL requestor object (created in main)
opener = None

# secret data to store in our encrypted database
class GriffinSecret(object):
    def __init__(self, id=None, key_id=None, schema=None, updated=None, data=None):
        self.id = id
        self.key_id = key_id
        self.schema = schema
        self.updated = updated
        self.data = data
    # human-readable string
    def __str__(self):
        props = {}
        for k, v in self.__dict__.iteritems():
            # don't display the data attribute
            if k == "data":
                continue
            props[k] = v
        return str(props)
    def __repr__(self):
        return self.__str__()
    # allow secrets to be compared for equality (mostly for testing)
    def __eq__(self, other):
        return (self.id == other.id and
                self.key_id == other.key_id and
                self.schema == other.schema and
                self.data == other.data)

# wrapper object to contain signing keys, encryption keys, and all the encrypted
# secrets that we can pickle and store to the filesystem
class GriffinKeySet(object):
    KEYFILE_NAME = "griffin.kdb"

    def __init__(self, keyfile=None):
        # absolute path to key file
        self.keyfile = keyfile
        self.version = 1
        self.ED25519_PRIVATE_KEY = None
        self.ED25519_VERIFY_KEY = None
        self.SALSA20_PRIVATE_KEY = None
        # email address of user
        self.email = None
        # dict of secrets: obviously not ACID compliant, but this is a
        # reference client, not intended for multi-threaded use
        self.secrets = {}

    # retrieve a secret by ID
    #
    # args: int id
    # returns: GriffinSecret, None if not found
    def get(self, id):
        return self.secrets.get(id, None)

    # retrieve secrets based on various search criteria
    def get_secrets(self, **kwargs):

        # method for determining if a secret matches search criteria
        def is_match(secret, **kwargs):
            for name, value in kwargs.iteritems():
                # "data__" prefix allows search inside data attribute
                if name.startswith("data__"):
                    name = name.split("data__")[1]
                    if secret.data.get(name) != value:
                        return False
                # "__gt" suffix allows searching for secrets with x > y
                elif name.endswith("__gt"):
                    name = name.split("__gt")[0]
                    if getattr(secret, name) <= value:
                        return False
                # search against other top-level attributes
                elif getattr(secret, name) != value:
                    return False
            # all criteria match
            return True

        # match secrets based on one or more search criteria
        matches = []
        # iterate through all of our secrets to look for matches
        for secret_id, secret in self.secrets.iteritems():
            if is_match(secret, **kwargs):
                matches.append(secret)

        # return any secrets that matched all search criteria (sorted by id)
        return sorted(matches, key=lambda s: s.id)

    # generate sigining and encryption keys, pickle them to the file system
    #
    # args: str key_dir directory to store keys in, str email address of user
    # returns: None
    def generate_keys(self, key_dir, email):
        # resolve the key directory into an absolute path
        key_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), key_dir)
        if not os.path.isdir(key_dir):
            raise ValueError("Directory does not exist: %s" % key_dir)
        key_name = os.path.join(key_dir, self.KEYFILE_NAME)
        # make sure keys don't already exist in this location
        if os.path.exists(key_name):
            raise ValueError("Keys already present: %s" % key_dir)

        # store the full path to our key file
        self.keyfile = key_name
        # generate the new random signing key
        signing_key = nacl.signing.SigningKey.generate()
        # generate the new symmetric encryption key
        encrypt_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        # encode and store our keys
        self.ED25519_PRIVATE_KEY = base64.b64encode(signing_key._seed)
        self.ED25519_VERIFY_KEY = base64.b64encode(signing_key.verify_key._key)
        self.SALSA20_PRIVATE_KEY = base64.b64encode(encrypt_key)
        # store the email address (username)
        self.email = email
        # persist to the file system
        self.save_to_disk()

    # read and unpickle a local GriffinKeySet from file and load properties
    #
    # args: str key_dir directory containing keys
    # returns: GriffinKeySet
    @classmethod
    def read_keys(cls, key_dir):
        # resolve the key directory into an absolute path
        key_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), key_dir)
        if not os.path.isdir(key_dir):
            raise ValueError("Directory does not exist: %s" % key_dir)
        kdb_name = os.path.join(key_dir, cls.KEYFILE_NAME)
        # make sure key file exists
        if not os.path.exists(kdb_name):
            raise ValueError("Keys not found in: %s" % key_dir)
        with open(kdb_name, "r") as fp:
            return pickle.load(fp)

    def get_next_id(self):
        if not self.secrets:
            return 1
        # find and increment the highest ID in our local keystore
        return max(self.secrets, key=lambda s: s.get("id")).get("id", 0) + 1

    def get_signing_key(self):
        return nacl.signing.SigningKey(base64.b64decode(self.ED25519_PRIVATE_KEY))

    def get_verify_key(self, b64=False):
        return nacl.signing.VerifyKey(base64.b64decode(self.ED25519_VERIFY_KEY))

    def get_encrypt_key(self):
        return base64.b64decode(self.SALSA20_PRIVATE_KEY)

    # store a JSON secret in our local store
    def save_secret(self, secret):
        # no ID specified, generate a new ID to use
        if secret.id is None:
            secret.id = self.get_next_id()
        # ID specified, determine if we need to update our existing record or skip
        # the update if the local copy is newer
        else:
            # do we have an existing copy with this ID and is it newer, if so
            # skip the update
            existing = self.get(secret.id)
            if existing is not None and existing.updated > secret.updated:
                return
        # the secret we were passed is newer than our copy, so store it
        self.secrets[secret.id] = secret
        self.save_to_disk()

    def save_to_disk(self):
        with open(self.keyfile, "wb") as fp:
            pickle.dump(self, fp)

    def delete_from_disk(self):
        if not os.path.exists(self.keyfile):
            raise ValueError("No keyfile found: %s" % self.keyfile)
        os.remove(self.keyfile)

# generate a new local key database to store encrypted secrets
#
# args: str key_dir directory to store key database in, str email address
# returns: GriffinKeySet
def generate_keyset(key_dir, email):
    keyset = GriffinKeySet()
    keyset.generate_keys(key_dir, email)
    return keyset

# read and unpickle a local keyset file and return the GriffinKeySet object
#
# args: str key_dir directory containing keys
# returns: GriffinKeySet
def read_keyset(key_dir):
    return GriffinKeySet.read_keys(key_dir)

# Sign a message using the signing key in the given keyset
#
# args: str msg, GriffinKeySet keyset
# returns: nacl.signing.SignedMessage
def sign_msg(msg, keyset):
    return keyset.get_signing_key().sign(msg)

# Verify a signed message using the verification key in the given keyset
#
# args: nacl.signing.SignedMessage signed_msg, GriffinKeySet keyset
# returns: msg if valid, raises nacl.exceptions.BadSignatureError if invalid
def verify_msg(signed_msg, keyset):
    return keyset.get_verify_key().verify(signed_msg)

# Encrypt a message using the symmetric encryption key in the given keyset
#
# args: str msg, GriffinKeySet keyset
# returns: EncryptedMessage
def encrypt_msg(msg, keyset):
    box = nacl.secret.SecretBox(keyset.get_encrypt_key())
    # nonce doesn't need to be secret but MUST be unique per message
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    return box.encrypt(msg, nonce)

# Decrypt a message using the symmetric encryption key in the given keyset
#
# args: EncryptedMessage encrypted_msg, GriffinKeySet keyset
# returns: str plaintext
def decrypt_msg(encrypted_msg, keyset):
    box = nacl.secret.SecretBox(keyset.get_encrypt_key())
    return box.decrypt(encrypted_msg)

# Return epoch time (seconds elapsed since epoch) also accounting for an
# optional timedelta
# args: datetime.timedelta delta
# returns: int seconds since epoch
def get_epoch_time_with_delta(delta = datetime.timedelta(0)):
    # calculate epoch based on UTC time to match PHP server behavior
    return int((datetime.datetime.utcnow() -
                datetime.datetime(1970,1,1) +
                delta).total_seconds())

# sign the relevant bits of a request
# TODO needs better doc
def sign_request(request, keyset):
    # request method
    method = request.get_method()
    # request content-type (or empty string if not set to match PHP server behavior)
    content_type = request.headers.get("Content-type", "")
    # URL path
    path = urlparse.urlparse(request.get_full_url()).path
    # request data
    data = request.get_data()
    # expire time for signed request (one minute from now)
    expires = str(get_epoch_time_with_delta(datetime.timedelta(minutes = 1)))

    # aggregate fields for signing
    message = json.dumps({
        "method": method,
        "content_type": content_type,
        "path": path,
        "data": data,
        "expires": expires
    })

    # sign over message fields with keyset
    return sign_msg(message, keyset)

# TODO needs doc
# args: str method, str data, GriffinKeySet keyset
# returns: str response body
def http_request(method, url, data = None, keyset = None):
    req = urllib2.Request(url = url, data = data)
    req.add_header("Content-Type", "application/json")
    req.get_method = lambda: method
    if keyset is not None:
        sig = base64.b64encode(sign_request(req, keyset))
        req.add_header("Authorization", "Griffin %s:%s" % (keyset.email, sig))
    # TODO factor this out into a generic request function so we can handle
    # exceptions more uniformly
    try:
        response = opener.open(req).read()
    except urllib2.HTTPError, err:
        response = err.read()
    except Exception, e:
        response = json.dumps({"status": "error", "details": str(e)})
    return response

# return a Griffin record from the server
# args: str record_id, str key_dir directory containing signing key
# returns: str record or error details
def get_record(record_id, key_dir):
    url = "%s://%s/griffin/record/%s" % (HTTP_SCHEME, GRIFFIN_HOST, record_id)
    return http_request("GET", url, key_dir = key_dir)

# send the full database to the server for synchronization
def send_full_pw_database():
    pass

# register a new user on the server
# args: GriffinKeySet keyset
# returns: str JSON response 
def register_user(keyset):
    url = "%s://%s/%s/user/" % (HTTP_SCHEME, GRIFFIN_HOST, GRIFFIN_PATH)
    data = json.dumps({"email": keyset.email, "pubkey": keyset.ED25519_VERIFY_KEY})
    return http_request("POST", url, data = data)

# deregister an existing user from the server
# args: GriffinKeySet keyset
# returns: str JSON response 
def deregister_user(keyset):
    url = "%s://%s/%s/user/" % (HTTP_SCHEME, GRIFFIN_HOST, GRIFFIN_PATH)
    return http_request("DELETE", url, keyset = keyset)

# create a new Griffin record on the server
# args:
#     str metadata cleartext metadata about record, str data encrypted data,
#     str key_dir directory containing signing and encryption keys,
# returns: str data about record created or error details
def create_record(metadata, data, key_dir):
    url = "%s://%s/griffin/record/" % (HTTP_SCHEME, GRIFFIN_HOST)
    data = json.dumps({"metadata": metadata, "data": data})
    return http_request("POST", url, data = data, key_dir = key_dir)

# send Griffin secrets for storage on the server
# args:
#     int age (in seconds) of Secrets to send to server,
#     str key_dir directory containing signing and encryption keys,
# returns: str data about record created or error details
def send_secrets(age, key_dir):
    url = "%s://%s/%s/secret/" % (HTTP_SCHEME, GRIFFIN_HOST, GRIFFIN_PATH)
    data = json.dumps({
        "secrets": [{
            "id": 2, "key_id": 1, "schema": 1,
            "age": age, "data": "abc123abc123abc123abc123abc123abc123"
        }]
    })
    # TODO encrypt data :-)
    return http_request("POST", url, data = data, key_dir = key_dir)

# turn a passphrase into a symmetric encryption key
#
# args: str passphrase
# returns: 32 bytes of key
def derive_key_from_passphrase(passphrase):
    # TODO NO, this is horrendously bad. Need an actual PBKDF like scrypt.
    return nacl.hash.sha256(passphrase)[:64].decode("hex")

def main(args):
    # probably want to factor this and other related items into a utils module
    global opener
    opener = build_http_opener(debuglevel=args.http_debug)

    if args.generate_keyset:
        generate_keyset(args.key_location, args.email)
    if args.create_record:
        sys.stdout.write(create_record(args.metadata, args.data, args.key_location))
    if args.get_record:
        sys.stdout.write(get_record(args.get_record, args.key_location))
    if args.register_user:
        sys.stdout.write(register_user(read_keyset(args.key_location)))
    if args.send_secrets:
        sys.stdout.write(send_secrets(args.age, args.key_location))

if __name__ == "__main__":
    args = parse_args()
    main(args)
