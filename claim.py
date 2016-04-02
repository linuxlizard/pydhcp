#!/usr/bin/env python3

# davep 16-Mar-2016 ; bulk claim several IP addresses

import sys
import logging

import bulk

logger = logging.getLogger("dhcp.claim")

if __name__=='__main__':
    logging.basicConfig(level=logging.DEBUG)

    num_to_claim = int(sys.argv[1])
    logfilename = sys.argv[2]

    bulk.claim_many(num_to_claim, logfilename)

