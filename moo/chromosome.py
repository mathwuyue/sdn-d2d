# -*- coding=utf-8
import random
import topo


def totuple(matrix):
        tmp = []

        for i in range(topo.num_nodes):
            tmp.extend(matrix[i])

        return tmp


def tomatrix(tuple):
    tmp = []
    for i in range(topo.num_nodes):
        tmp.append(tuple[i*topo.num_nodes:i*topo.num_nodes+topo.num_nodes])

    return tmp


def random_gen_chromo():
    tmp = []
    for i in range(topo.num_nodes * topo.num_nodes):
        j = random.random()

        # add new generation
        if j > 0.7:
            tmp.append(1)
        else:
            tmp.append(0)

    return chromosome(tmp)


class chromosome(object):
    """description of class"""

    def __init__(self, arg):
        if isinstance(arg, (list, tuple)):
            if isinstance(arg[0], list):
                self.matrix = arg
            else:
                self.matrix = tomatrix(arg)
