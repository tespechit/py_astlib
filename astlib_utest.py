import unittest

from use_astlib_test import amiuser
from use_astlib_test import amipass
from use_astlib_test import amiport
from use_astlib_test import amihost

from astlib import AstAMI


# python2 astlib_utest.py ValidTests
class ValidTests(unittest.TestCase):
    def test_1_is_dict(self):
        """
        Valid connect data, call get_all_channels_s()
        """
        ast_ami = AstAMI(**{'host': amihost, 'port': amiport, 'user': amiuser, 'password': amipass})
        channels = ast_ami.get_all_channels_s()
        self.assertIsInstance(channels, dict)


# python2 astlib_utest.py InValidTests
class InValidTests(unittest.TestCase):
    def test_2_except_on_err(self):
        """
        Invalid connect data, call get_all_channels_s()
        """
        ast_ami = AstAMI(**{'host': 'badhostname.local', 'port': amiport, 'user': amiuser, 'password': amipass})
        with self.assertRaises(Exception) as e:
            ast_ami.get_all_channels_s()
        print('\nBad Asterisk AMI address: %s' % e.exception)

    def test_3_except_on_err(self):
        """
        Invalid connect data, call get_all_channels_s()
        """
        ast_ami = AstAMI(**{'host': amihost, 'port': 66111, 'user': amiuser, 'password': amipass})
        with self.assertRaises(Exception) as e:
            ast_ami.get_all_channels_s()
        print('\nBad Asterisk AMI port: %s' % e.exception)


def main():
    unittest.main()


if __name__ == '__main__':
    main()

