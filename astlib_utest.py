import unittest
from pprint import pprint

from use_astlib_test import amiuser
from use_astlib_test import amipass
from use_astlib_test import amiport
from use_astlib_test import amihost

from astlib import AstMI

# python2 astlib_utest.py ValidTests
class ValidTests(unittest.TestCase):
    def test_1_is_tuple(self):
        """
        Valid connect data, call show_channels_s()
        """
        ast_ami = AstMI(**{'host': amihost, 'port': amiport, 'user': amiuser, 'password': amipass})
        channels = ast_ami.show_channels_s()
        self.assertIsInstance(channels, tuple)
        pprint(channels)

    def test_2_is_dict(self):
        """
        Valid connect data, call show_channels_s(key='channel')
        """
        ast_ami = AstMI(**{'host': amihost, 'port': amiport, 'user': amiuser, 'password': amipass})
        channels = ast_ami.show_channels_s(key='channel')
        self.assertIsInstance(channels, dict)


class CustomMethodTest(unittest.TestCase):
    def test_1_sip_peer_status(self):
        ast_ami = AstMI(**{'host': amihost, 'port': amiport, 'user': amiuser, 'password': amipass})
        sip_peers = ast_ami.sip_peer_status()
        self.assertIsInstance(sip_peers, tuple)
        pprint(sip_peers)


# python2 astlib_utest.py InValidTests
class InValidTests(unittest.TestCase):
    def test_2_except_on_err(self):
        """
        Invalid connect data, call show_channels_s()
        """
        ast_ami = AstMI(**{'host': 'badhostname.local', 'port': amiport, 'user': amiuser, 'password': amipass})
        with self.assertRaises(Exception) as e:
            ast_ami.show_channels_s()
        print('\nBad AMI address: %s' % e.exception)

    def test_3_except_on_err(self):
        """
        Invalid connect data, call show_channels_s()
        """
        ast_ami = AstMI(**{'host': amihost, 'port': 66111, 'user': amiuser, 'password': amipass})
        with self.assertRaises(Exception) as e:
            ast_ami.show_channels_s()
        print('\nBad AMI port: %s' % e.exception)


def main():
    unittest.main()


if __name__ == '__main__':
    main()

