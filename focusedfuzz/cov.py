import tracer
import os
from itertools import islice, izip
import collections
import logging
import functools
from . import qemu_runner
from .utils import replace_input_placeholder

logger = logging.getLogger("focusedfuzz.cov")

class DynamicTrace(object):
    def __init__(self, binary, input_file, target_opts=None,
                 input_placeholder='@@'):
        '''
        A class used to collect
        coverage of program under an input

        args:
        binary: the path to the program
        input_file: path to the input file

        '''
        self.binary = binary
        self.input_file = os.path.abspath(input_file)
        self.target_opts = target_opts
        self.input_placeholder = input_placeholder

        logger.debug("binary:%s", self.binary)
        logger.debug("input_file:%s", self.input_file)

        self.e_cov = collections.Counter([])
        self.n_cov = collections.Counter([])
	self.e_seed = {}	

        self._crash = False
        self._tmout = False

        self._collect_cov()


    def _collect_cov(self):
        if self.target_opts == None or self.input_placeholder not in self.target_opts:
            # the target program reads from stdin
            t = qemu_runner.QEMURunner(self.binary, input=file(self.input_file).read())
        else:
            opts = replace_input_placeholder(self.target_opts,
                                             self.input_file,
                                             self.input_placeholder)
            t = qemu_runner.QEMURunner(self.binary, input='', argv=[self.binary] + opts)

        if t.crash_mode:
            self._crash = True
        if t.tmout:
            self._tmout = True

        nodes = t.trace
        edges = izip(nodes, islice(nodes, 1, None))

        self.n_cov.update(collections.Counter(nodes))
        self.e_cov.update(collections.Counter(edges))
	self.e_seed = {}

    def crash(self):
        return self._crash

    def timeout(self):
        return self._tmout

    def edges(self):
        return self.e_cov.viewkeys()

    def nodes(self):
        return self.n_cov.viewkeys()

class AccCov(object):
    def __init__(self):
        self.acc_node_cov = collections.Counter([])
        self.acc_edge_cov = collections.Counter([])

        # this is for bookkeeping
        self.input_files = []
	self.acc_edge_seed = {}

    def add_trace(self, trace):

        self.input_files.append(trace.input_file)

        self.acc_edge_cov.update(trace.e_cov)
        self.acc_node_cov.update(trace.n_cov)
	for e in trace.e_cov:
		self.acc_edge_seed[e] = trace.input_file

    def nodes(self):
        return self.acc_node_cov.viewkeys()

    def edges(self):
        return self.acc_edge_cov.viewkeys()

    def leastCovered(self):
	minCov = 0
	minEdge = None
	for e in self.edge:
		count = sefl.acc_edge_cov[e]
		if  count < minCov or minCov == 0:
			minCov = count
			minEdge = e
	return minEdge

    def edge_seed(self, edge):
	return self.acc_edge_seed[edge]
