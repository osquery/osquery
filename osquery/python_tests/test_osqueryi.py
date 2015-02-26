import unittest

from test_base import OsqueryWrapper, OsqueryException, OsqueryUnknownException


class OsqueryiTest(unittest.TestCase):
    def setUp(self):
        self.osqueryi = OsqueryWrapper()

    def test_error(self):
        '''Test that we throw an error on bad query'''
        self.osqueryi.run_command(' ')
        self.assertRaises(OsqueryException, self.osqueryi.run_query, 'foo')

    def test_time(self):
        '''Demonstrating basic usage of OsqueryWrapper with the time table'''
        self.osqueryi.run_command(' ')  # flush error output
        result = self.osqueryi.run_query(
            'SELECT hour, minutes, seconds FROM time;')
        self.assertEqual(len(result), 1)
        row = result[0]
        self.assertTrue(0 <= int(row['hour']) <= 24)
        self.assertTrue(0 <= int(row['minutes']) <= 60)
        self.assertTrue(0 <= int(row['seconds']) <= 60)


if __name__ == '__main__':
    unittest.main()
