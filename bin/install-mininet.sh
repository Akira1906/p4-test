#! /bin/bash
# Copyright 2021 Andy Fingerhut
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0


# This script is just a tiny excerpt from install-p4dev-v4.sh for
# installing only Mininet.  My intent is to automate some extra
# visibility into how Mininet's installation is operating, in hopes of
# learning whether it is straightforward to stop it from installing
# Python2 when run on an Ubuntu 20.04 Desktop Linux system that
# doesn't already have Python2 installed.

set -x

THIS_SCRIPT_FILE_MAYBE_RELATIVE="$0"
THIS_SCRIPT_DIR_MAYBE_RELATIVE="${THIS_SCRIPT_FILE_MAYBE_RELATIVE%/*}"
THIS_SCRIPT_DIR_ABSOLUTE=`readlink -f "${THIS_SCRIPT_DIR_MAYBE_RELATIVE}"`

PATCH_DIR="${THIS_SCRIPT_DIR_ABSOLUTE}/patches"

lsb_release -a
python -V  || echo "No such command in PATH: python"
python2 -V || echo "No such command in PATH: python2"
python3 -V || echo "No such command in PATH: python3"
pip -V  || echo "No such command in PATH: pip"
pip2 -V || echo "No such command in PATH: pip2"
pip3 -V || echo "No such command in PATH: pip3"
pip list  || echo "No such command in PATH: pip"
pip2 list || echo "No such command in PATH: pip2"
pip3 list || echo "No such command in PATH: pip3"

find / | grep -v '^/proc' | sort > files-1-before-mininet.txt

git clone https://github.com/mininet/mininet mininet
cd mininet
patch -p1 < "${PATCH_DIR}/mininet-dont-install-python2.patch"
cd ..
sudo ./mininet/util/install.sh -nwv

python -V  || echo "No such command in PATH: python"
python2 -V || echo "No such command in PATH: python2"
python3 -V || echo "No such command in PATH: python3"
pip -V  || echo "No such command in PATH: pip"
pip2 -V || echo "No such command in PATH: pip2"
pip3 -V || echo "No such command in PATH: pip3"
pip list  || echo "No such command in PATH: pip"
pip2 list || echo "No such command in PATH: pip2"
pip3 list || echo "No such command in PATH: pip3"

find / | grep -v '^/proc' | sort > files-2-after-mininet.txt
diff files-1-before-mininet.txt files-2-after-mininet.txt > files-diff.txt
