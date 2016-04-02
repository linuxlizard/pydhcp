#!/usr/bin/env python3

# davep 16-Mar-2016 ; bulk release several IP addresses

import sys
import logging

import bulk

logger = logging.getLogger("dhcp.release")

if __name__=='__main__':
    logging.basicConfig(level=logging.DEBUG)

    logfilename = sys.argv[1]

    bulk.release_using_logfile(logfilename)
