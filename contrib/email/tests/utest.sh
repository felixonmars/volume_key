#
# Common test utilities.
#
# Copyright (C) 2018 Jiří Kučera <jkucera@redhat.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#

# Script name:
ME=""
# Script directory:
HERE=""
# Script's PID:
TEST_PID=0
# Log file:
TEST_LOG=""
# Temporary file:
TEST_TEMP=""
# LUKS passphrase used by tests:
TEST_PASSWD=""
# Test image:
TEST_IMG=""
# Test image backup:
TEST_IMG_BK=""
# Test packet:
TEST_PACKET=""
# Dry run flag (only print what's going on):
TEST_DRYRUN=0

export ME HERE TEST_PID TEST_LOG TEST_TEMP TEST_PASSWD
export TEST_IMG TEST_IMG_BK TEST_PACKET TEST_DRYRUN

# Array with tests:
declare -a TESTS

##
# initialize PATH_TO_SCRIPT
#
# Initialize script variables.
function initialize() {
  ME=$(basename $1)
  HERE=$(dirname $1)
  TEST_PID=$$
  TEST_LOG="$HERE/$ME.log"
  # Clear the log:
  echo -n "" > "$TEST_LOG"
  TEST_TEMP="/var/tmp/$ME$$.tmp"
  TEST_PASSWD="testluks"
  TEST_IMG="$HERE/$ME.img"
  TEST_IMG_BK="$TEST_IMG.bk"
  TEST_PACKET="$HERE/$ME.escrow"
  TEST_DRYRUN=0
}

##
# cleanup_
#
# Remove all except logs; occasionally, call `cleanup`.
function cleanup_() {
  [[ x$(type -t cleanup) != xfunction ]] || cleanup
  rm -f ${TEST_TEMP/[0-9]*./*.} $HERE/*.var
}

##
# info [-n] MESSAGE
#
# Write MESSAGE to the log and to the stdout. `-n` prevents end lines.
function info() {
  local T

  [[ "$1" == -n ]] && { T="$1"; shift; }
  echo $T "$*" | tee -a $TEST_LOG
}

##
# error MESSAGE
#
# Print error MESSAGE and exit.
function error() {
  echo "$ME: $*" >&2
  exit 1
}

##
# fecho FILE [WORD1 WORD2 ...]
#
# Put each WORD# to FILE, one WORD# per line.
function fecho() {
  local F

  F=$1
  [[ "$F" ]] && shift && (
    while [[ $# -gt 0 ]]; do
      echo "$1"
      shift
    done
  ) > $F
}

##
# underline STRING [CHAR]
#
# Underline STRING with the given CHAR (default is `=`).
function underline() {
  info "$1"
  info "${1//?/${2:-=}}"
}

##
# banner
#
# Print intro banner.
function banner() {
  local T

  info ""
  underline "[$(date '+%Y-%m-%d %H:%M:%S %z')] Running $ME$1:"
  info ""
}

##
# re_escape TEXT
#
# Escape regexp special characters.
function re_escape() {
  local P

  P="${1//\\/\\\\}"
  P="${P//\./\\.}"
  P="${P//\?/\\?}"
  P="${P//\[/\\[}"
  P="${P//\]/\\]}"
  P="${P//(/\\(}"
  P="${P//)/\\)}"
  P="${P//\'/@sq@}"
  echo -n "$P"
}

##
# enumerate_files DIR PATTERN
#
# Enumerate all files in DIR that matches PATTERN.
function enumerate_files() {
  for f in $(ls -a1 $1); do
    if [[ $f =~ ^$2$ ]]; then
      echo "$1/$f"
    fi
  done
}

##
# read_var NAME [DEFAULT]
#
# Read NAME's value from persistent storage. If NAME does not exist, return
# DEFAULT.
function read_var() {
  [[ -f $HERE/$TEST_PID-$1.var ]] && cat $HERE/$TEST_PID-$1.var || echo -n "$2"
}

##
# write_var NAME VALUE
#
# Write VALUE to persistent storage under the NAME.
function write_var() {
  echo -n $2 > $HERE/$TEST_PID-$1.var
}

##
# wait_file FILE DURATION
#
# Wait until FILE appears, but no longer than DURATION seconds. Fails if FILE
# does not appear during waiting.
function wait_file() {
  local T

  T=$2
  until [[ $T -le 0 || -f "$1" ]]; do
    sleep 1
    T=$(( T - 1 ))
  done
  [[ -f "$1" ]]
}

##
# create_fake_script FILE [EXITCODE]
#
# Create an executable script that always exits with EXITCODE (0 as default).
function create_fake_script() {
  (
    echo '#!/bin/bash'
    echo ""
    echo "exit ${2:-0}"
  ) > $1 && chmod a+x $1
}

##
# remove_file FILE
#
# Remove FILE.
function remove_file() {
  runcmd -s "Removing $1" \
            "rm -f $1"
}

##
# remove_dir DIR
#
# Remove DIR.
function remove_dir() {
  runcmd -s "Removing $1" \
            "rm -rfd $1"
}

##
# empty_dir DIR
#
# Remove the content of DIR.
function empty_dir() {
  runcmd -s "Removing $1's content" \
            "rm -rf $1/*"
}

##
# assert_equal A B DETAILS
#
# Fail if A != B; also print DETAILS about A and B comparison.
function assert_equal() {
  runcmd "Checking if $3" \
         "[[ $1 -eq $2 ]]"
}

##
# assert_linematch FILE PATTERN
#
# Check if FILE contains at least one line matching PATTERN.
function assert_linematch() {
  runcmd "Checking if $1 contains line that matches ${2//@sq@/\\\'}" \
         "[[ \"\$(cat $1 | sed -e s/\'/@sq@/g | grep -E '^$2$')\" ]]"
}

##
# assert_nofile FILE
#
# Check if FILE is not a file or does not exist.
function assert_nofile() {
  runcmd "Checking if $1 is not a file" \
         "[[ ! -f $1 ]]"
}

##
# assert_identical FILE1 FILE2
#
# Check whether FILE1 and FILE2 are identical.
function assert_identical() {
  runcmd "Checking if $1 and $2 are identical" \
         "diff $1 $2"
}

##
# assert_empty_dir DIR
#
# Check whether DIR is empty.
function assert_empty_dir() {
  runcmd "Checking if $1 is empty" \
         "[[ -z \"\$(ls -A $1)\" ]]"
}

##
# runcmd [ -s | --soft ] INFO COMMAND [EXITCODE]
#
# Print INFO about what's going on and run COMMAND. If --soft is given, do not
# terminate process when error occurrs. Also test if COMMAND ends with EXITCODE
# (default EXITCODE is 0).
function runcmd() {
  local E
  local S
  local X

  S=0
  [[ "x$1" =~ ^x-s|x--soft$ ]] && { S=1; shift; }
  X=${3:-0}
  info -n "$1... "
  (
    if [[ $TEST_DRYRUN -ne 0 ]]; then
      echo "[DRY RUN] $2"
    else
      eval "$2"
    fi
  ) > $TEST_TEMP 2>&1
  E=$?
  if [[ $E -eq $X ]]; then
    info "ok"
  else
    info "FAILED"
  fi
  cat $TEST_TEMP | while read L; do info ">>> $L"; done
  [[ $E -eq $X ]] || [[ $S -eq 1 ]] || { [[ $E -eq 0 ]] && exit 1; } || exit $E
}

##
# dophase PHASE
#
# Perform a PHASE, where PHASE is usually a user defined function. For internal
# use only.
function dophase() {
  local E

  [[ x$(type -t $1) != xfunction ]] && error "function was expected"
  ( eval $1 ); E=$?
  [[ $E -ne 0 ]] && { info "==[ FAILED ]=="; cleanup_; exit $E; }
  info "==[ PASSED ]=="
}

##
# runtests OPTIONS
#
# Run all tests. OPTIONS are:
#
#   -h, -?, --help    print help and exit
#   --dry-run         only print what's going on
#   --debug           also print what's bash doing
#   --setup           run setup only
#   --cleanup         do cleanup manually
#
function runtests() {
  local D
  local P
  local S

  D=0
  S=0
  for P; do
    case $P in
      -h | -? | --help)
        echo "$ME [ -h | -? | --help | --dry-run | --debug | --setup | --cleanup ]"
        echo ""
        echo "Options:"
        echo ""
        echo "  -h, -?, --help    print this screen and exit"
        echo "  --dry-run         only print what's going on"
        echo "  --debug           also print what's bash doing"
        echo "  --setup           run setup only"
        echo "  --cleanup         do cleanup manually"
        echo ""
        exit 0
        ;;
      --dry-run)
        TEST_DRYRUN=1
        ;;
      --debug)
        D=1
        ;;
      --setup)
        S=1
        ;;
      --cleanup)
        cleanup_
        exit 0
        ;;
      *)
        error "invalid option: $P"
        ;;
    esac
  done
  [[ $D -ne 0 ]] && set -x
  dophase setup
  [[ $S -ne 0 ]] && exit 0
  for t in ${TESTS[@]}; do
    dophase $t
  done
  cleanup_
  info ""
  info "[[[ ALL TESTS PASSED ]]]"
  info ""
}
