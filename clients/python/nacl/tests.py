import unittest
import time

import client

class TestPythonClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keyset = client.generate_keyset("/tmp")

    @classmethod
    def tearDownClass(cls):
        cls.keyset.delete_from_disk()

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
        secret_2 = self.keyset.secrets.pop()
        # compare the properties of the original and reconstituted secrets
        self.assertEqual(secret_1.id, secret_2.id)
        self.assertEqual(secret_1.key_id, secret_2.key_id)
        self.assertEqual(secret_1.schema, secret_2.schema)
        self.assertEqual(secret_1.updated, secret_2.updated)
        self.assertEqual(secret_1.data, secret_2.data)

if __name__ == "__main__":
    unittest.main()

