#!/usr/bin/env python3
# Copyright (c) 2017-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Class which wraps BitcoinTestFramework functionality"""

import argparse
import os, sys
import logging
import shutil
import tempfile
import configparser

from .test_framework import BitcoinTestFramework, TestStatus, SkipTest, TEST_EXIT_PASSED, TEST_EXIT_FAILED, TEST_EXIT_SKIPPED, TMPDIR_PREFIX
from .mininode import NetworkThread
from .authproxy import JSONRPCException
from .util import (
    PortSeed,
    check_json_precision
)

class TestWrapper(BitcoinTestFramework):
    """Wrapper Class for BitcoinTestFramework.

    Provides the BitcoinTestFramework rpc & daemon process management
    functionality to external python projects."""

    def set_test_params(self):
        # This can be overriden in setup() parameter.
        self.num_nodes=3

    def run_test(self):
        pass

    def setup(self,
        bitcoind=os.path.abspath(os.path.dirname(os.path.realpath(__file__)) + "/../../../src/bitcoind"),
        bitcoincli=None,
        setup_clean_chain=True,
        num_nodes=3,
        network_thread=None,
        rpc_timeout=60,
        supports_cli=False,
        bind_to_localhost_only=True,
        nocleanup=False,
        noshutdown=False,
        cachedir=os.path.abspath(os.path.dirname(os.path.realpath(__file__)) + "/../../cache"),
        tmpdir=None,
        loglevel='INFO',
        trace_rpc=False,
        port_seed=os.getpid(),
        coveragedir=None,
        configfile=os.path.abspath(os.path.dirname(os.path.realpath(__file__)) + "/../../config.ini"),
        usecli = False,
        perf = False):

        self.setup_clean_chain = setup_clean_chain
        self.num_nodes = num_nodes
        self.network_thread = network_thread
        self.rpc_timeout = rpc_timeout
        self.supports_cli = supports_cli
        self.bind_to_localhost_only = bind_to_localhost_only

        self.options = argparse.Namespace
        self.options.nocleanup = nocleanup
        self.options.noshutdown = noshutdown
        self.options.cachedir = cachedir
        self.options.tmpdir = tmpdir
        self.options.loglevel = loglevel
        self.options.trace_rpc = trace_rpc
        self.options.port_seed = port_seed
        self.options.coveragedir = coveragedir
        self.options.configfile = configfile
        self.options.pdbonfailure = False # Not supported.
        self.options.usecli = usecli
        self.options.perf = perf

        self.options.bitcoind = bitcoind
        self.options.bitcoincli = bitcoincli

        PortSeed.n = self.options.port_seed
        os.environ['PATH'] = self.options.bitcoind + ":" + os.environ['PATH']

        check_json_precision()

        self.options.cachedir = os.path.abspath(self.options.cachedir)

        config = configparser.ConfigParser()
        config.read_file(open(self.options.configfile))
        self.config = config

        # Set up temp directory and start logging
        if self.options.tmpdir:
            self.options.tmpdir = os.path.abspath(self.options.tmpdir)
            os.makedirs(self.options.tmpdir, exist_ok=False)
        else:
            self.options.tmpdir = tempfile.mkdtemp(prefix=TMPDIR_PREFIX)
        self._start_logging()

        self.log.debug('Setting up network thread')
        self.network_thread = NetworkThread()
        self.network_thread.start()

        try:
            if self.options.usecli:
                if not self.supports_cli:
                    raise SkipTest("--usecli specified but test does not support using CLI")
                self.skip_if_no_cli()
            self.skip_test_if_missing_module()
            self.setup_chain()
            self.setup_network()
        except JSONRPCException:
            self.log.exception("JSONRPC error")
        except Exception:
            self.log.exception("Unexpected exception caught during testing")
        except KeyboardInterrupt:
            self.log.warning("Exiting after keyboard interrupt")
        # Attaching PDB on failure is not supported.


    def shutdown(self):
        self.log.debug('Closing down network thread')
        self.network_thread.close()
        if not self.options.noshutdown:
            self.log.info("Stopping nodes")
            if self.nodes:
                self.stop_nodes()
        else:
            for node in self.nodes:
                node.cleanup_on_exit = False
            self.log.info("Note: bitcoinds were not stopped and may still be running")

        should_clean_up = (
            not self.options.nocleanup and
            not self.options.noshutdown and
            not self.options.perf
        )
        if should_clean_up:
            self.log.info("Cleaning up {} on exit".format(self.options.tmpdir))
            cleanup_tree_on_exit = True
        elif self.options.perf:
            self.log.warning("Not cleaning up dir {} due to perf data".format(self.options.tmpdir))
            cleanup_tree_on_exit = False
        else:
            self.log.warning("Not cleaning up dir {}".format(self.options.tmpdir))
            cleanup_tree_on_exit = False

        logging.shutdown()

        if cleanup_tree_on_exit:
            shutil.rmtree(self.options.tmpdir)

        # Newly initialized nodes will be appended during setup again.
        self.nodes.clear()