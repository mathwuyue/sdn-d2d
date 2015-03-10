# -*- coding=utf-8
num_nodes = 6 * 11


class topo(object):
    """Define the network topology in the class"""

    def __init__(self):
        self.edge = [[0 for col in range(num_nodes)] for row in range(num_nodes)];

        for i in range(num_nodes):
            for j in range(i, num_nodes):
                # define network topology
                if (j == i + 1 or j == i - 1 or j == i + 10) and ((int)(i / 11) == (int) (j / 11)):
                    self.edge[i][j] = 1
                elif j == i + 11 or j == i - 11:
                    self.edge[i][j] = 1

#        for i in range(8):
#            for j in range(8):
#                if self.edge[i][j] != 0:
#                    self.edge[j][i] = self.edge[i][j]
