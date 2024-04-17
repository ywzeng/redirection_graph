# -*-coding: utf-8 -*-

"""
@author: zyw
@file  : measure_exp.py
@date  : 2024/2/3

The functions in this script focus on various measurements.
"""

import os
import networkx as nx

from urllib.parse import urlsplit
from pprint import pprint
from redirection_tree import Node, RedirectionTree
from typing import Optional
from info_extraction import extract_target_entries, get_parent_info, build_redirection_tree


def measure_degree_distribution():
    """
    Measure the in- and out-degree of the redirection samples.
    Here, we measure both the redirection chain-only case and the whole tree case.

    In order to enhance the importance of initiator node in the tree,
        we manually add an edge from the initiator node to the related redirection node in calculating the degrees.

    Noted, to facilitate finding the key redirection nodes, we label the edge 'B->A' when facing a request from A to B.
    An edge is represented as [cur_node, parent_node, parent_source],
        indicating that the cur_node is issued by the parent_node in the 'parent_source' way.

    1. Form the redirection tree;
    2. Extract the redirection nodes and the corresponding initiator nodes;
    3. Build the directed graph for whole tree and for chain-only, respectively.
    :return:
    """
    sample_source_dict = {
        'aliyun_1': r'E:\redirection_samples\aliyun\tag_info',
        'aliyun_2': r'E:\redirection_samples\aliyun\tag_info_2',
        'aliyun_3': r'E:\redirection_samples\aliyun\tag_info_3',
        'liang_1': r'E:\redirection_samples\liangzhizhou\tag_info',
        'liang_2': r'E:\redirection_samples\liangzhizhou\tag_info_2',
        'yan_1': r'E:\redirection_samples\yandingkui\tag_info',
        'yan_2': r'E:\redirection_samples\yandingkui\tag_info_2',
        'vmware_1': r'E:\redirection_samples\vmware\tag_info',
        'vmware_2': r'E:\redirection_samples\vmware\tag_info_2',
        'zeng_1': r'E:\redirection_samples\zengyuwei\tag_info',
        'zeng_2': r'E:\redirection_samples\zengyuwei\tag_info_2',
        'zeng_temp': r'E:\redirection_samples\zengyuwei\tag_info_temp',
        'xinda': r'E:\redirection_samples\xinda'
    }

    sample_list = list()
    # entry_file = r'./data/modified_malicious_entries.txt'     # prior samples
    entry_file = r'./data/cur_entries.txt'      # cur samples
    with open(entry_file, 'r', encoding='utf-8') as fr:
        for line in fr:
            line = line.strip('\n').split('\t')
            domain, source = line[0], line[2]
            end_url = line[3]
            sample_list += [[domain, source, end_url]]

    initiator_info_dict = dict()
    # initiator_file = r'./data/malicious_initiator_entries.txt'        # prior samples
    initiator_file = r'./data/cur_initiator_entries.txt'        # cur samples
    with open(initiator_file, 'r', encoding='utf-8') as fr:
        for line in fr:
            line = line.strip('\n').split('\t')
            domain, source = line[0], line[2]
            r_node_url, r_node_timestamp = line[3], line[5]
            initiator_url, initiator_timestamp = line[6], line[8]
            cur_initiator_info = [r_node_url, r_node_timestamp, initiator_url, initiator_timestamp]
            sample = domain + ':' + source
            if sample in initiator_info_dict:
                initiator_info_dict[sample] += [cur_initiator_info]
            else:
                initiator_info_dict[sample] = [cur_initiator_info]

    for sample_item in sample_list:
        domain, source, end_url = sample_item[0], sample_item[1], sample_item[2]
        sample = domain + ':' + source
        if source in sample_source_dict:        # prior samples
            sample_dir = str(os.path.join(sample_source_dict[source], domain))
        else:       # cur samples
            sample_dir = str(os.path.join(sample_source_dict['xinda'], source))
        entry_list = extract_target_entries(domain, sample_dir)
        parent_info_list = get_parent_info(entry_list)
        r_tree = build_redirection_tree(domain, parent_info_list)

        # Get redirection-related nodes.
        r_node_list = r_tree.get_intermediaries(None, end_url)
        i_node_list = list()
        i_r_pair_list = list()
        for item in initiator_info_dict[sample]:
            r_url, r_time, i_url, i_time = item[0], item[1], item[2], item[3]
            r_node = r_tree.exact_match_node(r_url, r_time)
            i_node = r_tree.exact_match_node(i_url, i_time)
            i_node_list += [i_node]
            i_r_pair = (i_node, r_node)     # [initiator_node, redirection_node]
            i_r_pair_list += [i_r_pair]

        # 1. Build directed graph for the whole tree.
        node_list = list()
        edge_list = list()
        # Traverse the tree to get the node connections with BFS.
        queue = [r_tree.root]
        while queue:
            cur_node = queue.pop(0)
            node_list += [cur_node]
            for child in cur_node.children_list:
                queue += [child]
                cur_edge = [cur_node, child, child.parent_source]
                edge_list += [cur_edge]
        # Additionally consider the implicit connection between redirection node and initiator node.
        for node_pair in i_r_pair_list:
            cur_edge = [node_pair[0], node_pair[1], node_pair[1].parent_source]
            if cur_edge in edge_list:
                continue
            edge_list += [cur_edge]
        # Construct the directed graph.
        tree_graph = nx.DiGraph()
        for i, node in enumerate(node_list):
            node_desc = 'v' + str(i)
            tree_graph.add_node(node, desc=node_desc)
        for edge in edge_list:
            tree_graph.add_edge(edge[0], edge[1], name=edge[2])
        print(tree_graph.degree())

        # 2. Build directed graph for the redirection chain.
        edge_list = list()
        for node in r_node_list[1:]:     # Skip the root node because it has no parent.
            cur_edge = [node.parent, node, node.parent_source]
            edge_list += [cur_edge]
        for node_pair in i_r_pair_list:
            cur_edge = [node_pair[0], node_pair[1], node_pair[1].parent_source]
            if cur_edge in edge_list:
                continue
            edge_list += [cur_edge]
        # Construct the directed graph.
        chain_graph = nx.DiGraph()
        for i, node in enumerate(r_node_list + i_node_list):
            node_desc = 'v' + str(i)
            chain_graph.add_node(node, desc=node_desc)
        for edge in edge_list:
            chain_graph.add_edge(edge[0], edge[1], name=edge[2])
        print(chain_graph.degree())
    

if __name__ == '__main__':
    pass
