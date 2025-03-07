#! /bin/bash
# Copyright 2023 Andy Fingerhut
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


# Try installing PTF on a system, and report detailed results about
# relevant vrsions of software installed.

if [ ! -r /etc/os-release ]
then
    1>&2 echo "No file /etc/os-release.  Cannot determine what OS this is."
    linux_version_warning
    exit 1
fi
source /etc/os-release
echo "Found ID ${ID} and VERSION_ID ${VERSION_ID} in /etc/os-release"

PIP_INSTALL_OPTS=""
if [ "${ID}" = "ubuntu" ]
then
    case "${VERSION_ID}" in
        23.04)
            PIP_INSTALL_OPTS="--break-system-packages"
            ;;
    esac
fi

if [ "${ID}" = "ubuntu" ]
then
    sudo apt-get --yes install git python3-pip
elif [ "${ID}" = "fedora" ]
then
    sudo dnf -y install git python3-pip
fi

set -x
set -e
python3 --version
pip3 --version

PTF_COMMIT="771a45249de2f287377b4690cd13adc18f989638"   # 2023-Jun-19
#git clone https://github.com/p4lang/ptf
git clone https://github.com/jafingerhut/ptf
cd ptf
#git checkout "${PTF_COMMIT}"
git checkout fix-issue-194
sudo pip install ${PIP_INSTALL_OPTS} .
