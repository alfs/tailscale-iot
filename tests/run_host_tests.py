#!/usr/bin/env python3
"""Compile actual HTTP/2 sources and protocol fixtures with ASan/UBSan.

Requires Python 3 and clang++; no ESPHome installation or live credentials.
The ESPHome stubs provide only logging, watchdog, clock and heap telemetry.
"""
import os
import sys
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
compiler = os.environ.get('CXX', 'clang++')
flags = ['-std=c++17', '-fsanitize=address,undefined', '-g',
         '-I' + str(root / 'tests/stubs'), '-I' + str(root / 'components/tailscale')]
with tempfile.TemporaryDirectory(prefix='tailscale-iot-host-') as directory:
    for name, sources in [
        ('http2', ['tests/http2_session_test.cpp', 'components/tailscale/http2_session.cpp']),
        ('hpack', ['tests/hpack_status_test.cpp']),
        ('noise-records', ['tests/noise_records_test.cpp']),
    ]:
        binary = str(Path(directory) / name)
        subprocess.run([compiler, *flags, *(str(root / s) for s in sources), '-o', binary], check=True)
        subprocess.run([binary], check=True)
        print(name + ': ASan/UBSan passed', flush=True)
    subprocess.run([compiler, '-std=c++17', '-fsyntax-only',
                    '-I' + str(root / 'tests/stubs'), '-I' + str(root / 'components/tailscale'),
                    '-I' + str(root / 'components/tailscale/noise/include'),
                    str(root / 'components/tailscale/ts2021_transport.cpp')], check=True)
    print('TS2021 transport: host syntax check passed')

subprocess.run([sys.executable, str(root / "tests/check_io_shutdown.py")], check=True)

subprocess.run([sys.executable, str(root / 'tests/check_peer_removal.py')], check=True)
