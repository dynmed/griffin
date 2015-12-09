import unittest
import time
import datetime
import re
import sys
import urllib2
import os.path
import json
import random

import client

# read the values from config.php into a local data structure
def read_config():
    config = {}
    fp = open(os.path.join(os.path.dirname(__file__),
                           "../griffin/config.php"), "r")
    for line in fp.readlines():
        match = re.match("^define\(\"(?P<name>\w+)\", \"(?P<value>\w+)\"\);", line)
        if match is not None:
            config[match.group("name")] = match.group("value")
    fp.close()
    return config

# execute a shell command
def exec_shell(cmd):
    rv = subprocess.call(cmd, shell=True)

class TestPythonClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        client.opener = client.build_http_opener(debuglevel=0)
        cls.APP_ROOT = client.GRIFFIN_PATH
        cls.PHP_CONFIG = read_config()

    def setUp(self):
        email = "test_user_%s@example.org" % ('%x' % random.randrange(2**32))
        self.keyset = client.generate_keyset("/tmp", email)

    def tearDown(self):
        try:
            self.keyset.delete_from_disk()
        except:
            pass

    # @unittest.skip("skipping")
    def test_save_secret(self):
        secret_1 = client.GriffinSecret(
            id = 42,
            key_id = 1,
            schema = 1,
            updated = time.strftime("%Y-%m-%d %H:%M:%S"),
            data = { "type": "website",
                     "domain": "example.com",
                     "username": "bob",
                     "password": "@pple$" }
        )
        # save the new secret, persisting it to disk
        self.keyset.save_secret(secret_1)

        # reconstitute the keyset from the file and confirm that
        # we can read the correct values out of it
        self.keyset = client.read_keyset("/tmp")
        self.assertEqual(len(self.keyset.secrets), 1)
        secret_2 = self.keyset.get(id = secret_1.id)
        # compare the properties of the original and reconstituted secrets
        self.assertEqual(secret_1, secret_2)

    # @unittest.skip("skipping")
    def test_get_secrets(self):
        NOW  = datetime.datetime.now()
        THEN = datetime.datetime.now() - datetime.timedelta(minutes = 5)

        secret_1 = client.GriffinSecret(
            id = 22,
            key_id = 1,
            schema = 1,
            updated = NOW.strftime("%Y-%m-%d %H:%M:%S"),
            data = { "type": "website",
                     "domain": "example.com",
                     "username": "alice",
                     "password": "@pple$" }
        )
        self.keyset.save_secret(secret_1)
        secret_2 = client.GriffinSecret(
            id = 42,
            key_id = 1,
            schema = 1,
            updated = THEN.strftime("%Y-%m-%d %H:%M:%S"),
            data = { "type": "website",
                     "domain": "example.com",
                     "username": "bob",
                     "password": "p!ckl3" }
        )
        self.keyset.save_secret(secret_2)
        secret_3 = client.GriffinSecret(
            id = 9,
            key_id = 1,
            schema = 1,
            updated = NOW.strftime("%Y-%m-%d %H:%M:%S"),
            data = { "type": "website",
                     "domain": "example.net",
                     "username": "alice",
                     "password": "gr@p3$" }
        )
        self.keyset.save_secret(secret_3)

        # test get_secrets by ID
        s = self.keyset.get_secrets(id = secret_1.id)
        self.assertEqual(s, [secret_1])

        # test get_secrets by domain
        s = self.keyset.get_secrets(data__domain = "example.com")
        self.assertEqual(s, [secret_1, secret_2])

        # test get_secrets by date range
        s = self.keyset.get_secrets(updated__gt = THEN.strftime("%Y-%m-%d %H:%M:%S"))
        self.assertEquals(s, [secret_3, secret_1])

        # test get_secrets by multiple criteria
        s = self.keyset.get_secrets(updated__gt = THEN.strftime("%Y-%m-%d %H:%M:%S"),
                                    data__domain = "example.net")
        self.assertEqual(s, [secret_3])

    # @unittest.skip("skipping")
    def test_save_secret(self):
        T1 = datetime.datetime.now()
        T0 = T1 - datetime.timedelta(minutes = 5)
        T2 = T1 + datetime.timedelta(minutes = 5)

        # test adding a secret to the empty store can be retrieved
        sec_1 = client.GriffinSecret(
            id = 22,
            key_id = 1,
            schema = 1,
            updated = T1.strftime("%Y-%m-%d %H:%M:%S"),
            data = { "password": "LOCAL_PASSWORD" }
        )
        self.keyset.save_secret(sec_1)
        sec_2 = self.keyset.get(id = sec_1.id)
        self.assertEqual(sec_1, sec_2)

        # test that saving a secret with an older timestamp does not overwrite
        # the existing secret
        sec_3 = client.GriffinSecret(
            id = 22,
            key_id = 1,
            schema = 1,
            updated = T0.strftime("%Y-%m-%d %H:%M:%S"),
            data = { "password": "REMOTE_PASSWORD" }
        )
        self.keyset.save_secret(sec_3)
        sec_4 = self.keyset.get(id = sec_3.id)
        # ensure we still have the old secret stored
        self.assertEqual(sec_4.data["password"], sec_1.data["password"])

        # test that saving a secret with a newer timestamp DOES overwrite
        # the existing secret
        sec_5 = client.GriffinSecret(
            id = 22,
            key_id = 1,
            schema = 1,
            updated = T2.strftime("%Y-%m-%d %H:%M:%S"),
            data = { "password": "NEW_SECURE_PASSWORD" }
        )
        self.keyset.save_secret(sec_5)
        sec_6 = self.keyset.get(id = sec_5.id)
        # ensure we have the new secret stored
        self.assertEqual(sec_6.data["password"], sec_5.data["password"])

    # @unittest.skip("skipping")
    def test_sign_msg(self):
        MSG = "Attack at dawn!"
        signed_msg = client.sign_msg(MSG, self.keyset)
        verified = client.verify_msg(signed_msg, self.keyset)
        self.assertEqual(MSG, verified)

    # @unittest.skip("skipping")
    def test_encrypt_msg(self):
        MSG = "War is peace. Freedom is slavery. Ignorance is strength"
        encrypted_msg = client.encrypt_msg(MSG, self.keyset)
        decrypted_msg = client.decrypt_msg(encrypted_msg, self.keyset)
        self.assertEqual(MSG, decrypted_msg)

    # @unittest.skip("skipping")
    def test_register_user(self):
        resp = json.loads(client.register_user(self.keyset))
        # test that we successfully registered the user
        self.assertEqual(resp["status"], 201)
        self.assertEqual(resp["message"], "User Created")
        self.assertEqual(resp["email"], self.keyset.email)
        # test that we can't register the same email address
        resp = json.loads(client.register_user(self.keyset))
        self.assertEqual(resp["status"], 400)
        self.assertEqual(resp["message"], "User Already Exists")
        # test that we can deregister the existing user
        resp = json.loads(client.deregister_user(self.keyset))
        self.assertEqual(resp["status"], 200)
        self.assertEqual(resp["message"], "User Deregistered")

    # test that multiple clients updating the same secrets on the server
    # preserve the last-modified data in all local copies
    # @unittest.skip("skipping")
    def test_sync_secrets(self):
        # register user
        # resp = json.loads(client.register_user(self.keyset))
        client.register_user(self.keyset)

        T1 = datetime.datetime.now()
        T0 = T1 - datetime.timedelta(minutes = 5)
        T2 = T1 + datetime.timedelta(minutes = 5)

        # create a secret with updated timestamp of now
        secret_1 = client.GriffinSecret(
            id = 42,
            key_id = 1,
            schema = 1,
            updated = T0.strftime("%Y-%m-%d %H:%M:%S"),
            data = { "type": "website",
                     "domain": "example.com",
                     "username": "alice",
                     "password": "@pple$" }
        )
        self.keyset.save_secret(secret_1)

        # TODO not sure this is actually necessary for this test
        # tell the client to send any secrets updated in the last 5 minutes
        client.send_secrets(600, self.keyset)

        # test that we can sync secrets between two clients
        sync_code = self.keyset.wrap_keys()

        # create second client: same user account, different keyset
        if not os.path.exists("/tmp/keyset_2"):
            os.makedirs("/tmp/keyset_2")

        keyset_2 = client.generate_keyset("/tmp/keyset_2", self.keyset.email)

        # fetch keys for the second client using the sync code generated by the first
        keys = keyset_2.fetch_synced_keys(sync_code)
        keyset_2.import_keys(keys)

        # request existing secrets from server
        secrets = client.request_secrets(600, keyset_2)
        print "[INFO] secrets: %s" % secrets

        # delete the second keyset (first one gets cleaned up by tearDown)
        keyset_2.delete_from_disk()

        # deregister the user
        resp = json.loads(client.deregister_user(self.keyset))


if __name__ == "__main__":
    unittest.main()

