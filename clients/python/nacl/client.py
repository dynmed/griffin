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

# parse a list of command line arguments and return a data structure containing
# the configuration options
def parse_args(args = None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--generate-keypair", dest="generate_signing_key",
                        action="store_true",
                        help="Generate a new signing key pair for the Ed25519 algorithm")
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
    return int((datetime.datetime.now() -
                datetime.datetime(1970,1,1) +
                delta).total_seconds())

# sign the relevant bits of a request
# TODO needs better doc
def sign_request(request, key_dir):
    # request method
    method = request.get_method()
    # request content-type (or empty string if not present)
    content_type = request.headers.get("Content-type", "")
    # URL path
    path = urlparse.urlparse(request.get_full_url()).path
    # request data (or empty string if not present)
    data = request.get_data() or ""
    # expire time for signed request
    expires = str(get_epoch_time_with_delta(datetime.timedelta(minutes = 1)))

    # concatenate fields together for signing
    message_fields = "\n".join([method, content_type, path, data, expires])
    
    # sign over message fields with keys in key directory
    return sign_msg(message_fields, key_dir)

# return a Griffin record from the server
# args: str record_id, str key_dir directory containing signing key
def get_record(record_id, key_dir):
    req = urllib2.Request(url = "http://localhost/griffin/record/%s" % record_id)
    sig = base64.b64encode(sign_request(req, key_dir))
    req.add_header("Authorization", "Griffin brandon@hackmill.com:%s" % sig)
    req.add_header("Host", "griffin.local")
    # TODO factor this out into a generic request function so we can handle
    # exceptions more uniformly
    return opener.open(req).read()

def main(args):
    # probably want to factor this and other related items into a utils module
    global opener
    opener = build_http_opener(debuglevel=args.http_debug)

    if args.generate_signing_key:
        generate_signing_key(args.key_location)
    if args.sign_msg:
        sys.stdout.write(sign_msg(args.msg, args.key_location))
    if args.get_record:
        sys.stdout.write(get_record(args.get_record, args.key_location))

if __name__ == "__main__":
    args = parse_args()
    main(args)
