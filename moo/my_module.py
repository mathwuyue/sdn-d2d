# -*- coding=utf-8
from PyGMO.problem import base
import topo
from chromosome import *

topology = topo.topo()


class my_problem(base):
    """
    De Jong (sphere) function implemented purely in Python.
 
    USAGE: my_problem(dim = 10)

    * dim problem dimension
    """
    def __init__(self, dim=64, start=0, end=1):
        # First we call the constructor of the base class telling
        # essentially to PyGMO what kind of problem to expect (1 objective, 0 contraints etc.)
        super(my_problem, self).__init__(dim)

        # then we set the problem bounds (in this case equal for all components)
        self.set_bounds(-5.12, 5.12)

        # we define some additional 'private' data members (not really necessary in
        # this case, but ... hey this is a tutorial)
        self.__dim = dim
        self.__start = start
        self.__end = end

    # We reimplement the virtual method that defines the objective function.
    def _objfun_impl(self, x):
        start = self.__start
        end = self.__end
        f = 0
        chromo = chromosome(x)
        while start != end:
            oldstart = start
            for i in range(topo.num_nodes):
                if chromo.matrix[start][i] == 1 and topology.edge[start][i] != 0:
                    f += topology.edge[start][i]
                    start = i
                    break
            # no repeat
            if oldstart == start:
                break

        if start != end:
            f = 1000000

        return (f, )

    # Finally we also reimplement a virtual method that adds some output to the __repr__ method
    def human_readable_extra(self):
        return "\n\t Problem dimension: " + str(self.__dim)
