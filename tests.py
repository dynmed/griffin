import unittest
import urllib2
import json
import sys
import subprocess
import re

# read the values from config.php into a local data structure
def read_config():
    config = {}
    fp = open("griffin/config.php", "r")
    for line in fp.readlines():
        match = re.match("^define\(\"(?P<name>\w+)\", \"(?P<value>\w+)\"\);", line)
        if match is not None:
            config[match.group("name")] = match.group("value")
    fp.close()
    return config

# container to read-in values from config.php
CONFIG_PHP = read_config()

def build_http_opener(debuglevel = 0):
    http = urllib2.HTTPHandler(debuglevel)
    return urllib2.build_opener(http)

# execute a shell command
def exec_shell(cmd):
    rv = subprocess.call(cmd, shell=True)

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

def drop_database():
    cmd = 'echo "drop database griffin" | mysql -u%s -p%s' % (CONFIG_PHP["DB_USER"],
                                                              CONFIG_PHP["DB_PASSWORD"])
    exec_shell(cmd)

if __name__ == "__main__":
    # drop the griffin database so we can test a fresh install
    if "--drop-db" in sys.argv:
        drop_database()

    # run the full suite of unit tests
    else:
        unittest.main()
