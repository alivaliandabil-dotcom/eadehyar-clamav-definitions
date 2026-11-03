import datetime
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    'definitions', Path(__file__).resolve().parents[1] / 'scripts/export-official-definitions.py'
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FreshnessTests(unittest.TestCase):
    def version(self, delta):
        date = datetime.datetime.now(datetime.timezone.utc) + delta
        return 'ClamAV 1.5.4/28173/' + date.strftime('%a %b %d %H:%M:%S %Y')

    def test_current(self):
        module.assert_current(self.version(datetime.timedelta(hours=-1)))

    def test_old(self):
        with self.assertRaises(ValueError):
            module.assert_current(self.version(datetime.timedelta(hours=-49)))

    def test_future(self):
        with self.assertRaises(ValueError):
            module.assert_current(self.version(datetime.timedelta(hours=1)))

    def test_malformed(self):
        for value in ['unknown', '', 'ClamAV/28173/2026-11-03', 'ClamAV 1.5.4/x/invalid']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.assert_current(value)
