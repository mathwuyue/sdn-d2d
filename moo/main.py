# -*- coding=utf-8
'''
Created on 2014

@author: Yue Wu
'''
from PyGMO import *
from my_algorithm import *
from my_module import my_problem
import topo
from moo import *
from chromosome import *

if __name__ == '__main__':

    #f = open("C:/pygmo.txt", 'w');

    #topology = topo.topo()
    #chromo = random_gen_chromo()
    #prob = my_problem(dim=topo.num_nodes * topo.num_nodes)
    #algo = my_algorithm()
    #pop = population(prob)
    #for i in range(50):
    #    pop.push_back(totuple(random_gen_chromo().matrix))
    ##print pop.get_best_idx
    ##for i in range(5):
    #algo.evolve(pop)
    #print pop[pop.get_best_idx()].best_f
    #matrix = tomatrix(pop[pop.get_best_idx()].best_x)

    moo = MOO(0, 12)

    best_f, matrix = moo.calc_path()


    #for i in range(topo.num_nodes):
    #    row = list(matrix[i])
    #    for j in range(topo.num_nodes):
    #        if topology.edge[i][j] == 0:
    #            row[j] = 0.0
    #    matrix[i] = row
    #for row in matrix:
    #    f.write(str(row) + '\n')
