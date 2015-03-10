# -*- coding=utf-8

from PyGMO import *
from chromosome import *
import random


class my_algorithm(algorithm.base):
    """
    Monte-Carlo (random sampling) algorithm implemented purely in Python.
    """

    def __init__(self, iter=10):
            """
            Constructs a Monte-Carlo (random sampling) algorithm

            USAGE: algorithm.my_algorithm(iter = 10)

            NOTE: At the end of each iteration, the randomly generated
                    point substitutes the worst individual in the population if better

            * iter: number of random samples
            """
            # We start calling the base constructor
            super(my_algorithm, self).__init__()
            # We then define the algorithm 'private' data members
            self.__iter = iter

    # Performs a very simple crossover step
    def cross(self, ind1, ind2):
        x1 = totuple(ind1.matrix)
        x2 = totuple(ind2.matrix)
        return chromosome(tuple(random.choice((x1[i], x2[i],)) for i in xrange(len(x1))))

    # Gaussian mutation
    def mutate(self, x, lb, ub):
        # Implementation of the Gaussian operator
        def _g_op(i):
            return min(max(random.gauss(x[i], (ub[i]-lb[i]) * 0.1), lb[i]), ub[i])

        # Condition for the mutation to happen
        def _rnd_mut():
            return random.random() < self.__p_m
        # return mutation value
        return tuple(_g_op(i) if _rnd_mut() else x[i] for i in xrange(len(x)))

    # This is the 'juice' of the algorithm, the method where the actual optimzation is coded.
    def evolve(self, pop):
            # If the population is empty (i.e. no individuals) nothing happens
            if len(pop) == 0:
                    return pop

            # Here we rename some variables, in particular the problem
            prob = pop.problem
            # Its dimensions (total and continuous)
            dim, cont_dim = prob.dimension, prob.dimension - prob.i_dimension
            # And the lower/upper bounds for the chromosome
            lb, ub = prob.lb, prob.ub

            # The algorithm now starts manipulating the population
            for _ in range(self.__iter):
                # we push back in the population
                pop.push_back(totuple(random_gen_chromo().matrix))
                # to then remove the worst individual
                pop.erase(pop.get_worst_idx())
            # at the end of it all we return the 'evolved' population
            return pop

    def get_name(self):
        return "Monte Carlo (Python)"

    def human_readable_extra(self):
        return "n_iter=" + str(self.__n_iter)
