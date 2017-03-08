# Copyright (C) 2016 DNAnexus, Inc.
#
# This file is part of dx-toolkit (DNAnexus platform client libraries).
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may not
#   use this file except in compliance with the License. You may obtain a copy
#   of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.

import sys
import subprocess
import dxpy

from sys import platform
NOTEBOOK_APP = 'app-notebook_server'
LOUPE_APP = 'app-10x_loupe_server'
SLEEP_PERIOD = 5

def setup_ssh_tunnel(job_id, local_port, remote_port):
    cmd = 'dx ssh --suppress-running-check {0}  -o "StrictHostKeyChecking no" -f -L {1}:localhost:{2} -N'.format(job_id, local_port, remote_port)
    subprocess.check_call(cmd, shell=True)


def multi_platform_open(cmd):
    if platform == "linux" or platform == "linux2":
        cmd = 'xdg-open {0}'.format(cmd)
    elif platform == "darwin":
        cmd = 'open {0}'.format(cmd)
    elif platform == "win32":
        cmd = 'start {0}'.format(cmd)
    subprocess.check_call(cmd, shell=True)


def run_notebook(args):
    input_files = ' '.join(['-iinput_files={0}'.format(f) for f in args.notebook_files])
    cmd = 'dx run {0} -inotebook_type={1} {2} -itimeout={3} -y --brief --allow-ssh --instance-type {4} '
    cmd = cmd.format(NOTEBOOK_APP, args.notebook_type, input_files, args.timeout, args.instance_type)
    job_id = subprocess.check_output(cmd, shell=True).strip()

    if args.notebook_type == 'jupyter':
        remote_port = 8888
    elif args.notebook_type == 'rstudio':
        remote_port = 8787

    setup_ssh_tunnel(job_id, args.port, remote_port)
    multi_platform_open('http://localhost:{0}'.format(args.port))

def run_loupe(args):
    input_files = ' '.join(['-iloupe_files={0}'.format(f) for f in args.loupe_files])
    cmd = 'dx run {0} {1} -itimeout={2} -y --brief --allow-ssh --instance-type {3} '
    cmd = cmd.format(LOUPE_APP, input_files, args.timeout, args.instance_type)
    job_id = subprocess.check_output(cmd, shell=True).strip()

    # Wait until the server is running
    sys.stdout.write('Waiting for Loupe server to initialize ...')
    sys.stdout.flush()
    while('ready' not in dxpy.describe(job_id)['tags']):
        subprocess.check_call('sleep {0}'.format(SLEEP_PERIOD), shell=True)
        sys.stdout.write('.')
        sys.stdout.flush()

    remote_port = 3000

    setup_ssh_tunnel(job_id, args.port, remote_port)
    multi_platform_open('http://localhost:{0}'.format(args.port))
