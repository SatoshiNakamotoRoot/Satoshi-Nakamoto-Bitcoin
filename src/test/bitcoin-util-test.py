#!/usr/bin/python
# Copyright 2014 BitPay, Inc.
# Distributed under the Expat software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import os
import bctest

if __name__ == '__main__':
	bctest.bctester(os.environ["srcdir"] + "/test/data",
			"bitcoin-util-test.json")

