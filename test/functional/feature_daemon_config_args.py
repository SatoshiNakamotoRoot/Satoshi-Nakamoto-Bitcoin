#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test -daemon config arg options."""

from test_framework.test_framework import BitcoinTestFramework


class DaemonConfigArgsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.usecli = True
        self.num_nodes = 3

    def test_daemon(self):
        self.log.info('Test -daemon config arg options')
        self.stop_nodes()

        self.log.debug('Test -daemon=0')
        with self.nodes[0].assert_debug_log(expected_msgs=['Command-line arg: daemon="0"\n']):
            self.start_node(0, extra_args=['-daemon=0'])
        self.stop_node(0)

        self.log.debug('Test -nodaemon')
        with self.nodes[0].assert_debug_log(expected_msgs=['Command-line arg: daemon=false\n']):
            self.start_node(0, extra_args=['-nodaemon'])
        self.stop_node(0)

        self.log.debug('Test -nodaemon=1')
        with self.nodes[0].assert_debug_log(expected_msgs=['Command-line arg: daemon=false\n']):
            self.start_node(0, extra_args=['-nodaemon=1'])
        self.stop_node(0)

        self.log.debug('Test -daemon')
        with self.nodes[1].assert_debug_log(expected_msgs=['Command-line arg: daemon=""\n']):
            self.nodes[1].start(extra_args=["-daemon"])
        self.nodes[1].wait_until_stopped(timeout=200)

        self.log.debug('Test -daemon="1"')
        with self.nodes[2].assert_debug_log(expected_msgs=['Command-line arg: daemon="1"\n']):
            self.nodes[2].start(extra_args=["-daemon=1"])
        self.nodes[2].wait_until_stopped(timeout=200)

    def run_test(self):
        self.test_daemon()


if __name__ == '__main__':
    DaemonConfigArgsTest().main()
