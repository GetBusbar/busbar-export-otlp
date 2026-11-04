#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run one harness command with inherited output and a finite completion deadline."""

import argparse
import math
import os
import shlex
import signal
import subprocess
import sys
import time

TIMEOUT_EXIT = 124
UNAVAILABLE_EXIT = 127
SIGNAL_EXIT_OFFSET = 128
SIGNAL_POLL_SECONDS = 1


def positive_seconds(text):
    try:
        seconds = int(text)
        if seconds <= 0 or not math.isfinite(float(seconds)):
            raise ValueError
    except (ValueError, OverflowError):
        raise argparse.ArgumentTypeError("timeout must be positive whole seconds") from None
    return seconds


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("seconds", type=positive_seconds)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.command:
        parser.error("a command is required")
    interrupted = []

    def remember_signal(signum, _frame):
        interrupted.append(signum)

    signal.signal(signal.SIGINT, remember_signal)
    signal.signal(signal.SIGTERM, remember_signal)
    # An inherited ignored CHLD must not auto-reap the leader before its group is cleaned up.
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    shown = shlex.join(args.command)
    try:
        # The command and its children have a group of their own. No sibling suite or daemon
        # belongs to it; containers are removed separately by their registered exact names.
        child = subprocess.Popen(args.command, start_new_session=True)
    except OSError as error:
        print(f"otlp: cannot start {shown}: {error}", file=sys.stderr)
        return UNAVAILABLE_EXIT
    deadline = time.monotonic() + args.seconds
    try:
        while True:
            if interrupted:
                signum = interrupted[0]
                print(f"otlp: {shown} interrupted by signal {signum}", file=sys.stderr)
                return SIGNAL_EXIT_OFFSET + signum
            # Observe completion without reaping. Keeping the group leader's PID reserved until
            # group cleanup prevents a finished command's PID from being reused by a sibling.
            ended = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if ended is not None:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                print(f"otlp: {shown} timed out after {args.seconds}s", file=sys.stderr)
                return TIMEOUT_EXIT
            time.sleep(min(remaining, SIGNAL_POLL_SECONDS))
    finally:
        # KILL also reaches children left behind by a completed leader, including ones ignoring
        # TERM or retaining an output pipe. The group still belongs to this unreaped child.
        # A group left with only the unreaped leader has no process to signal: Linux answers ESRCH,
        # Darwin EPERM (a zombie cannot be signalled). Either way nothing of the group is running.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        child.wait()
    if interrupted:
        signum = interrupted[0]
        print(f"otlp: {shown} interrupted by signal {signum}", file=sys.stderr)
        return SIGNAL_EXIT_OFFSET + signum
    result = child.returncode
    return SIGNAL_EXIT_OFFSET - result if result < 0 else result


if __name__ == "__main__":
    sys.exit(main())
