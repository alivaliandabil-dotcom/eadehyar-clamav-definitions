import datetime
import importlib.util
from pathlib import Path
import unittest
import tempfile


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


class CacheBoundaryTests(unittest.TestCase):
    def test_signed_vendor_sidecars_survive_cached_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ['main.cvd', 'daily.cvd', 'bytecode.cvd', 'freshclam.dat',
                         'main-63.cvd.sign', 'daily-28173.cvd.sign', 'bytecode-339.cvd.sign']:
                (root / name).write_bytes(b'synthetic-cache-entry')
            module.assert_cache_entries(root)

    def test_unknown_files_and_symlinks_remain_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unknown = root / 'unrelated.txt'
            unknown.write_text('synthetic')
            with self.assertRaises(ValueError):
                module.assert_cache_entries(root)
            unknown.unlink()
            (root / 'main.cvd').symlink_to('/does-not-exist')
            with self.assertRaises(ValueError):
                module.assert_cache_entries(root)

    def test_oversized_signature_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'daily-28173.cvd.sign').write_bytes(b'x' * (64 * 1024 + 1))
            with self.assertRaises(ValueError):
                module.assert_cache_entries(root)
