#!/usr/bin/env bash
# SGAI — double-click launcher for macOS.
#
# Finder runs ".command" files in Terminal on double-click (it will NOT run a
# bare ".sh"). This just hands off to run.sh from the repo directory.
#
# First time only: macOS may say it can't verify the developer. If so, right-click
# the file → Open → Open, or run:  xattr -d com.apple.quarantine run.command
cd "$(dirname "$0")" || exit 1
exec bash ./run.sh
