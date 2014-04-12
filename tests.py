import unittest
import urllib2
import json
import sys

def build_http_opener(debuglevel = 0):
    http = urllib2.HTTPHandler(debuglevel)
    return urllib2.build_opener(http)

class TestTransaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.APP_ROOT = "griffin"
        cls.opener = build_http_opener(debuglevel = ("--verbose" in sys.argv))

    def test_basic_request(self):
        req = urllib2.Request(url = "http://localhost/%s/foo/42" % self.APP_ROOT)
        req.add_header("Host", "griffin.local")
        resp = json.loads(self.opener.open(req).read())
        self.assertEqual(resp["fid"], 42)

if __name__ == "__main__":
    unittest.main()
