# Python reference client for Griffin Password Manager
import nacl.encoding
import nacl.signing
import argparse
import os
import sys
import urllib2
import urlparse
import datetime
import base64
import json

# parse a list of command line arguments and return a data structure containing
# the configuration options
def parse_args(args = None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--generate-keypair", dest="generate_signing_key",
                        action="store_true",
                        help="Generate a new signing key pair for the Ed25519 algorithm")
    parser.add_argument("--dump-verify-key", dest="dump_verify_key",
                        action="store_true",
                        help="Dump base64 encoded verify key to the console")
    parser.add_argument("--key-location", dest="key_location", action="store",
                        help="Directory to store the keys in")
    parser.add_argument("--sign-msg", dest="sign_msg", action="store_true",
                        help="Sign a message using the key in the given location")
    parser.add_argument("--msg", dest="msg", action="store",
                        help="Message to sign")
    parser.add_argument("--get-record", dest="get_record", action="store",
                        help="Get a Griffin record from the server")
    parser.add_argument("--http-debug", dest="http_debug", action="store_true",
                        help="Print verbose HTTP requests and responses")
    parser.add_argument("--run-dev-tests", dest="run_dev_tests", action="store_true",
                        help="Run development tests")
    args = parser.parse_args()
    # validate the arg combinations, etc.
    if args.generate_signing_key and args.key_location is None:
        parser.error("--generate-keypair requires --key-location also be specified")
    if args.sign_msg:
        if args.msg is None:
            parser.error("--sign-msg requires --msg be specified")
        if args.key_location is None:
            parser.error("--sign-msg requires --key-location also be specified")
    if args.get_record is not None and args.key_location is None:
        parser.error("--get-record requires --key-location also be specified")
    if args.dump_verify_key and args.key_location is None:
        parser.error("--dump-verify-key requires --key-location also be specified")
    return args

# create and return a URL-fetching object
# args: int debuglevel (1 for verbose HTTP output)
# returns: urllib2.OpenerDirector
def build_http_opener(debuglevel = 0):
    http = urllib2.HTTPHandler(debuglevel)
    return urllib2.build_opener(http)

# URL requestor object (created in main)
opener = None

# Generate and store a new signing key pair used in the Ed25519 algorithm
# args: str key_dir directory to store keys in
def generate_signing_key(key_dir):
    # resolve the key directory into an absolute path
    key_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), key_dir)
    if not os.path.isdir(key_dir):
        raise ValueError("Directory does not exist: %s" % key_dir)
    s_keyname = os.path.join(key_dir, "griffin.key")
    v_keyname = os.path.join(key_dir, "griffin.pub")
    # make sure keys don't already exist in this location
    if os.path.exists(s_keyname) or os.path.exists(v_keyname):
        raise ValueError("Keys already present: %s" % key_dir)
    # generate the new random signing key
    print "Generating Ed25519 signing keys in %s" % key_dir
    signing_key = nacl.signing.SigningKey.generate()
    # store the private key seed
    with open(s_keyname, "w") as fp:
        fp.write(signing_key._seed)
    # store verification key
    with open(v_keyname, "w") as fp:
        fp.write(signing_key.verify_key._key)

def dump_verify_key(key_dir):
    # resolve the key directory into an absolute path
    key_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), key_dir)
    if not os.path.isdir(key_dir):
        raise ValueError("Directory does not exist: %s" % key_dir)
    v_keyname = os.path.join(key_dir, "griffin.pub")
    # read in the public key from the key directory
    with open(v_keyname) as fp:
        verify_key = nacl.signing.VerifyKey(fp.read())
    # dump base64 encoded verify key to the console
    sys.stdout.write(base64.b64encode(verify_key._key))

# Sign a message using the signing key in the given directory
# args: str msg, str key_dir directory containing signing key
# returns: nacl.signing.SignedMessage
def sign_msg(msg, key_dir):
    # resolve the key directory into an absolute path
    key_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), key_dir)
    if not os.path.isdir(key_dir):
        raise ValueError("Directory does not exist: %s" % key_dir)
    s_keyname = os.path.join(key_dir, "griffin.key")
    # read in the signing key from the key directory
    with open(s_keyname) as fp:
        signing_key = nacl.signing.SigningKey(fp.read())
    return signing_key.sign(msg)

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
def sign_request(request, key_dir):
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

    # sign over message fields with keys in key directory
    return sign_msg(message, key_dir)

# TODO needs doc
def http_request(method, url, data = None, key_dir = None):
    req = urllib2.Request(url = url, data = data)
    sig = base64.b64encode(sign_request(req, key_dir))
    req.add_header("Authorization", "Griffin brandon@hackmill.com:%s" % sig)
    req.add_header("Host", "griffin.local")
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
    url = "http://griffin.local/griffin/record/%s" % record_id
    return http_request("GET", url, key_dir = key_dir)

# send the full database to the server for synchronization
def send_full_pw_database():
    pass

def run_dev_tests():
    req = urllib2.Request(url = "http://griffin.local/griffin/record/",
                          data = '{"metadata": "whee", "data":"this is the encrypted stuff..."}')
    req = urllib2.Request(url = "http://griffin.local/griffin/record/1")
    req.add_header("Content-Type", "application/json")
    # req.get_method = lambda: "POST"
    sig = base64.b64encode(sign_request(req, "/tmp"))
    print sig

def main(args):
    # probably want to factor this and other related items into a utils module
    global opener
    opener = build_http_opener(debuglevel=args.http_debug)

    if args.generate_signing_key:
        generate_signing_key(args.key_location)
    if args.dump_verify_key:
        dump_verify_key(args.key_location)
    if args.sign_msg:
        sys.stdout.write(sign_msg(args.msg, args.key_location))
    if args.get_record:
        sys.stdout.write(get_record(args.get_record, args.key_location))
    if args.run_dev_tests:
        run_dev_tests()

if __name__ == "__main__":
    args = parse_args()
    main(args)
