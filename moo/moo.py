# -*- coding=utf-8

from PyGMO import *
from my_algorithm import *
from my_module import my_problem
import topo
from chromosome import *


class MOO(object):
    """description of class"""

    def __init__(self, start_idx, end_idx):
        prob = my_problem(dim=topo.num_nodes * topo.num_nodes, start=start_idx, end=end_idx)
        self.topology = topo.topo()
        self.algo = my_algorithm()
        self.pop = population(prob)
        self.__start = start_idx
        self.__end = end_idx

    def calc_path(self):
        for i in range(50):
            self.pop.push_back(totuple(random_gen_chromo().matrix))
        # print pop.get_best_idx
        # for i in range(5):
        self.algo.evolve(self.pop)
        print self.pop[self.pop.get_best_idx()].best_f
        matrix = tomatrix(self.pop[self.pop.get_best_idx()].best_x)

        for i in range(topo.num_nodes):
            row = list(matrix[i])
            for j in range(topo.num_nodes):
                if self.topology.edge[i][j] == 0:
                    row[j] = 0.0
            matrix[i] = row

        ret = None
        if self.pop[self.pop.get_best_idx()].best_f[0] != 1000000:
            ret = [self.__start, ]
            cur = self.__start

            while cur != self.__end:
                for i in range(topo.num_nodes):
                    if matrix[cur][i] == 1.0:
                        ret.append(i)
                        cur = i
                        break

        return ret
