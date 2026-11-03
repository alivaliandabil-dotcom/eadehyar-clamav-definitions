"""Fetch signed public CVDs using FreshClam; never mount app files or credentials."""

import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


IMAGE = 'clamav/clamav@sha256:26509520043b68576c95e76576673d90b423fccb765dc8cba3a9fdc143891bf5'
FILES = ('main.cvd', 'daily.cvd', 'bytecode.cvd')


def assert_cache_entries(directory):
    for file in directory.iterdir():
        signature = re.fullmatch(r'(?:main|daily|bytecode)-\d+\.cvd\.sign', file.name)
        limit = 256 * 2**20 if file.name in FILES else 64 * 1024
        if (file.is_symlink() or not file.is_file() or
                (file.name not in (*FILES, 'freshclam.dat') and not signature) or
                file.stat().st_size > limit):
            raise ValueError('Unexpected cache entries are preserved and rejected.')


def run(args, **options):
    return subprocess.run(args, capture_output=True, text=True, timeout=300, **options)


def required(args, **options):
    result = run(args, **options)
    if result.returncode:
        raise RuntimeError('Official definition preparation failed; private diagnostics suppressed.')
    return result.stdout.strip()


def assert_current(version):
    matched = re.fullmatch(r'ClamAV \d+\.\d+\.\d+[^/\r\n]*/\d+/(.+)', version)
    if not matched:
        raise ValueError('Unrecognized official definition version.')
    timestamp = datetime.datetime.strptime(matched[1], '%a %b %d %H:%M:%S %Y').replace(
        tzinfo=datetime.timezone.utc
    )
    age = (datetime.datetime.now(datetime.timezone.utc) - timestamp).total_seconds()
    if age < -300 or age > 48 * 3600:
        raise ValueError('Official definitions are outside the unchanged freshness window.')


def export(output):
    if output.exists():
        raise ValueError('Existing output is preserved; choose a new isolated directory.')
    required(['docker', 'pull', IMAGE])
    uid, gid = required([
        'docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'sh', IMAGE,
        '-c', 'id -u clamav; id -g clamav',
    ]).split()
    with tempfile.TemporaryDirectory(prefix='official-cvd-') as temporary:
        work = Path(temporary)
        work.chmod(0o755)
        cached = os.environ.get('CVD_CACHE_DIR')
        data = Path(cached) if cached else work / 'definitions'
        if not data.is_absolute() or data.is_symlink():
            raise ValueError('An isolated absolute definition cache is required.')
        data.mkdir(mode=0o777, exist_ok=True)
        assert_cache_entries(data)
        data.chmod(0o777)
        fixtures = work / 'fixtures'
        fixtures.mkdir(mode=0o755)
        present = [(data / name).exists() for name in FILES]
        if any(present) and not all(present):
            raise ValueError('Incomplete cached definitions are preserved and rejected.')
        if not any(present):
            seed = required(['docker', 'create', IMAGE])
            try:
                required(['docker', 'cp', seed + ':/var/lib/clamav/.', str(data)])
            finally:
                required(['docker', 'rm', seed])
        required([
            'docker', 'run', '--rm', '--network', 'none', '--user', '0', '--read-only',
            '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--security-opt', 'no-new-privileges',
            '--mount', f'type=bind,src={data},dst=/var/lib/clamav', '--entrypoint', 'chown',
            IMAGE, '-R', uid + ':' + gid, '/var/lib/clamav',
        ])
        # docker cp preserves image ownership; only the matching unprivileged UID writes.
        config = work / 'freshclam.conf'
        config.write_text(
            'DatabaseDirectory /var/lib/clamav\nDatabaseOwner clamav\n'
            'DatabaseMirror database.clamav.net\nDNSDatabaseInfo current.cvd.clamav.net\n'
            'ScriptedUpdates no\nTestDatabases yes\nMaxAttempts 1\n'
            'ConnectTimeout 15\nReceiveTimeout 60\nForeground yes\n'
        )
        config.chmod(0o644)
        common = [
            'docker', 'run', '--rm', '--user', uid + ':' + gid, '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--memory', '3g', '--memory-swap', '3g', '--cpus', '2', '--pids-limit', '64',
            '--env', 'TZ=UTC', '--mount', f'type=bind,src={data},dst=/var/lib/clamav',
            '--tmpfs', f'/tmp:rw,noexec,nosuid,size=96m,uid={uid},gid={gid}',
        ]
        result = run(common + [
            '--mount', f'type=bind,src={config},dst=/etc/clamav/freshclam.conf,readonly',
            '--entrypoint', 'freshclam', IMAGE,
            '--config-file=/etc/clamav/freshclam.conf', '--stdout',
        ])
        if result.returncode:
            raise RuntimeError('Official FreshClam update rejected (exit ' + str(result.returncode) +
                               '); no definitions published and no retry performed.')
        version = required(common + ['--network', 'none', '--entrypoint', 'clamd', IMAGE, '--version'])
        assert_current(version)
        (fixtures / 'clean.pdf').write_bytes(b'%PDF-1.4\nSynthetic antivirus acceptance\n%%EOF')
        (fixtures / 'pattern.txt').write_bytes(
            b'X5O!P%@AP[4' + b'\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        )
        result = run(common + [
            '--network', 'none', '--mount', f'type=bind,src={fixtures},dst=/fixtures,readonly',
            '--entrypoint', 'clamscan', IMAGE, '--no-summary',
            '/fixtures/clean.pdf', '/fixtures/pattern.txt',
        ])
        if (result.returncode != 1 or '/fixtures/clean.pdf: OK' not in result.stdout or
                '/fixtures/pattern.txt:' not in result.stdout or ' FOUND' not in result.stdout):
            raise RuntimeError('Official database load/clean/pattern acceptance failed.')
        metadata = {}
        exported = list(FILES)
        for name in FILES:
            file = data / name
            if not file.is_file() or file.is_symlink() or not 512 < file.stat().st_size < 256 * 2**20:
                raise ValueError('Only bounded, signed CVD database files may be exported.')
            metadata[name] = {'bytes': file.stat().st_size, 'sha256': hashlib.sha256(file.read_bytes()).hexdigest()}
            header = file.read_bytes()[:512].decode('ascii').split(':')
            if header[0] != 'ClamAV-VDB' or not header[2].isdigit():
                raise ValueError('Unexpected signed CVD header.')
            signature_name = file.stem + '-' + header[2] + '.cvd.sign'
            signature = data / signature_name
            if (signature.is_symlink() or not signature.is_file() or
                    not 1 < signature.stat().st_size <= 64 * 1024):
                raise ValueError('Matching upstream CVD signature is required.')
            metadata[signature_name] = {'bytes': signature.stat().st_size, 'sha256': hashlib.sha256(signature.read_bytes()).hexdigest()}
            exported.append(signature_name)
        output.mkdir(mode=0o755)
        for name in exported:
            shutil.copyfile(data / name, output / name)
        receipt = {
            'createdAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'image': IMAGE, 'version': version, 'source': 'database.clamav.net',
            'officialFreshclamExit': 0, 'testDatabases': True, 'freshnessHours': 48,
            'cleanAccepted': True, 'harmlessPatternRejected': True, 'files': metadata,
            'applicationFilesOrCredentialsMounted': False,
        }
        (output / 'acceptance.json').write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps(receipt))


if __name__ == '__main__':
    try:
        export(Path(sys.argv[1]).resolve())
    except (RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
