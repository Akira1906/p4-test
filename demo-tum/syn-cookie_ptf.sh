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


# T="`realpath ../testlib`"
# if [ x"${PYTHONPATH}" == "x" ]
# then
#     P="${T}"
# else
#     P="${T}:${PYTHONPATH}"
# fi

P='/home/tristan/p4dev-python-venv/bin/python'

echo "P is: $P"

# Only show a list of tests
#ptf --pypath "$P" --test-dir ptf --list
#exit 0

set -x
p4c --target bmv2 \
    --arch v1model \
    --p4runtime-files syn-cookie/p4src/proxy.p4info.txtpb \
    syn-cookie/p4src/proxy.p4
    -o syn-cookie/p4src/proxy.json

# Remove any log file written in an earlier run, otherwise
# simple_switch_grpc will append the new log messages to the end of
# the existing file.
/bin/rm -f ss-log.txt

sudo simple_switch_grpc \
     --log-file syn-cookie_ss-log \
     --log-flush \
     --dump-packet-data 10000 \
     -i 0@veth0 \
     -i 1@veth2 \
     -i 2@veth4 \
     --thrift-port 9091 \
     --no-p4 &
echo ""
echo "Started simple_switch_grpc.  Waiting 2 seconds before starting PTF test ..."
sleep 2
    #  -i 3@veth6 \
    #  -i 4@veth8 \
    #  -i 5@veth10 \
    #  -i 6@veth12 \
    #  -i 7@veth14 \
# Note that the mapping between switch port number and Linux interface
# names is best to make it correspond with those given when starting
# the simple_switch_grpc process.  The `ptf` process has no other way
# of getting this mapping other than by telling it on its command
# line.
# source /home/tristan/p4dev-python-venv/bin/activate
echo "Start SYN-Cookie Control Plane application"
cd syn-cookie/p4-utils
python3 controller.py &
cd ../..

sudo -E ${P4_EXTRA_SUDO_OPTS} $(which ptf) \
    --pypath "$P" \
    -i 0@veth1 \
    -i 1@veth3 \
    -i 2@veth5 \
    --test-params="grpcaddr='localhost:9559';p4info='syn-cookie/p4src/proxy.p4info.txtpb';config='syn-cookie/p4src/proxy.json'" \
    --test-dir ptf
    # -i 3@veth7 \
    # -i 4@veth9 \
    # -i 5@veth11 \
    # -i 6@veth13 \
    # -i 7@veth15 \

echo ""
echo "PTF test finished.  Waiting 2 seconds before killing simple_switch_grpc ..."
sleep 2
sudo pkill --signal 9 --list-name simple_switch
echo ""
echo "Verifying that there are no simple_switch_grpc processes running any longer in 4 seconds ..."
sleep 4
ps axguwww | grep simple_switch
