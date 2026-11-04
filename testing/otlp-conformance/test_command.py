#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Behavioral sources for command.py; no collector, Docker daemon or compiler required."""

from pathlib import Path
import signal
import subprocess
import sys
import unittest

HELPER = Path(__file__).with_name("command.py")
# Room for a loaded runner to start the nested fixture interpreter (or let the leader exit)
# before the helper's deadline; the timeout test still finishes well inside TEST_WAIT_SECONDS.
COMMAND_SECONDS = 3
TEST_WAIT_SECONDS = 10
FIXTURE_FAILSAFE_SECONDS = TEST_WAIT_SECONDS * 2
TIMEOUT_EXIT = 124
SIGNAL_EXIT_OFFSET = 128
FIXTURE_EXIT = 7
READY = "command and child started"

# The child inherits stdout. communicate() cannot finish if a timed-out/interrupted helper
# leaves that child alive. The fixture's finite sleep also cleans up a regressed helper.
GROUP_FIXTURE = """
import signal, subprocess, sys, time
subprocess.Popen([sys.executable, '-c', 'import time; time.sleep({seconds})'])
print({ready!r}, flush=True)
time.sleep({seconds})
""".format(seconds=FIXTURE_FAILSAFE_SECONDS, ready=READY)


class CommandTests(unittest.TestCase):
    def command(self, seconds, program):
        return [sys.executable, "-I", str(HELPER), str(seconds), sys.executable, "-c", program]

    def test_success_preserves_output_and_the_commands_exit_status(self):
        result = subprocess.run(
            self.command(TEST_WAIT_SECONDS,
                         f"import sys; print('out'); print('err', file=sys.stderr); sys.exit({FIXTURE_EXIT})"),
            capture_output=True, text=True, timeout=TEST_WAIT_SECONDS,
        )
        self.assertEqual(result.returncode, FIXTURE_EXIT)
        self.assertEqual(result.stdout, "out\n")
        self.assertEqual(result.stderr, "err\n")

    def test_timeout_finishes_the_owned_group_and_retains_its_output(self):
        result = subprocess.run(
            self.command(COMMAND_SECONDS, GROUP_FIXTURE),
            capture_output=True, text=True, timeout=TEST_WAIT_SECONDS,
        )
        self.assertEqual(result.returncode, TIMEOUT_EXIT)
        self.assertIn(READY, result.stdout)
        self.assertIn("timed out", result.stderr)

    def test_a_completed_leader_does_not_leave_a_child_holding_the_output_pipe(self):
        program = (
            "import subprocess, sys; "
            f"subprocess.Popen([sys.executable, '-c', 'import time; time.sleep({FIXTURE_FAILSAFE_SECONDS})']); "
            f"print({READY!r}, flush=True); sys.exit({FIXTURE_EXIT})"
        )
        result = subprocess.run(
            self.command(COMMAND_SECONDS, program),
            capture_output=True, text=True, timeout=TEST_WAIT_SECONDS,
        )
        self.assertEqual(result.returncode, FIXTURE_EXIT)
        self.assertIn(READY, result.stdout)

    def test_term_finishes_the_owned_group_and_reaps_the_command(self):
        helper = subprocess.Popen(
            self.command(TEST_WAIT_SECONDS, GROUP_FIXTURE),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            self.assertEqual(helper.stdout.readline().strip(), READY)
            helper.send_signal(signal.SIGTERM)
            _stdout, stderr = helper.communicate(timeout=TEST_WAIT_SECONDS)
            self.assertEqual(helper.returncode, SIGNAL_EXIT_OFFSET + signal.SIGTERM)
            self.assertIn("interrupted by signal", stderr)
        finally:
            if helper.poll() is None:
                helper.kill()
            helper.communicate(timeout=TEST_WAIT_SECONDS)


if __name__ == "__main__":
    unittest.main()
