# -*-coding: utf-8 -*-

"""
@author: zyw
@file  : spiderweb_dataset.py
@date  : 2024/4/13
"""

import os

from pprint import pprint
from urllib.parse import urlsplit
from typing import Optional
from publicsuffixlist import PublicSuffixList


psl = PublicSuffixList(accept_unknown=False, only_icann=True)


def load_redirection_chains(sample: Optional[str] = None, label: Optional[str] = None) -> Optional[dict]:
    """
    Load the redirection chain of each sample.
    :param sample: 'domain:source'
    :param label: 'malicious' or 'benign'
    :return: {sample1: [url1, url2, ...], sample2: [url1, url2, ...], ...}
    """
    m_sample_file = r'../../data/modified_malicious_entries.txt'
    c_sample_file = r'../../data/cur_entries.txt'
    b_sample_file = r'../../data/modified_benign_entries.txt'

    sample_file_list = [m_sample_file, c_sample_file, b_sample_file]
    if label == 'malicious':
        sample_file_list = sample_file_list[:2]
    elif label == 'benign':
        sample_file_list = [b_sample_file]
    elif label:
        return None

    chain_dict = dict()
    found = False
    for sample_file in sample_file_list:
        if found:
            break
        with open(sample_file, 'r', encoding='utf-8') as fr:
            for line in fr:
                line = line.strip('\n').split('\t')
                cur_sample = line[0] + ':' + line[2]
                chain = line[4].split(' ')
                if sample:
                    if cur_sample == sample:
                        chain_dict[cur_sample] = chain
                        found = True
                        break
                else:
                    chain_dict[cur_sample] = chain

    return chain_dict


def aggregate_chains(chain_dict: dict) -> dict:
    """
    Aggregate the final URLs based on the similarity criterion used in the paper, namely 'Domain+Page+Parameters'.
    'Page' here indicates the file name of the Webpage.
    'Parameters' here indicates the param name in the URL.
    :param chain_dict:
    :return: {rule1: [chain1, chain2, ...], rule2: [chain1, chain2, ...], ...}
    """
    final_groups = dict()
    for sample in chain_dict:
        chain = chain_dict[sample]
        cur_final_url = chain[-1]
        url_parts = urlsplit(cur_final_url)
        domain = url_parts.netloc
        page = url_parts.path.split('/')[-1]
        params = ';'.join([p.split('=')[0] for p in url_parts.query.split('&')])
        cur_rule = '%s+%s+%s' % (domain, page, params)
        if cur_rule in final_groups:
            final_groups[cur_rule] += [chain]
        else:
            final_groups[cur_rule] = [chain]

    return final_groups


def get_webpage_params(url: str) -> list:
    """
    Given a URL, extract the following params:
        1. URL;
        2. Domain;
        3. Domain Length;
        4. TLD;
        5. URL Filename;
        6. URL Params;
    :param url:
    :return:
    """
    url_parts = urlsplit(url)
    domain = url_parts.netloc
    # Ignore the explicitly introduced port.
    if ':' in domain:
        domain = domain.split(':')[0]
    domain_len = len(domain)
    tld = psl.publicsuffix(domain)      # TLD is None if the domain is IP-format.
    url_filename = url_parts.path.split('/')[-1]
    url_params = ';'.join([p.split('=')[0] for p in url_parts.query.split('&')])

    return [url, domain, domain_len, tld, url_filename, url_params]


def construct_redirection_graph(chain_dict: dict) -> dict:
    """
    Aggregate the chains with similar finial nodes into graphs in the following steps:
        1. Aggregate the chains whose final URLs are in the same final group;
        2. Construct the various sets in each group to represent the RedGraph.
    Each graph is represented as: RedGraph=<R, C_rg, U_rg, G_rg, Ref_rg, Lan_rg, Fin_rg>.
    Construct the following parts:
        1. Webpage-related params:
            1.1. URL;
            1.2. Domain;
            1.3. Domain Length;
            1.4. TLD;
            1.5. URL Filename;
            1.6. URL Params;
        2. Redirection chain:
            2.1. Vertex set;
            2.2. Edge set;
            2.3. Referer node;
            2.4. Final node: fin_node;
        3. Redirection graph:
            3.1. Final node (Here we use the rule of the final URL set);
            3.2. Distinct redirection chain set;
            3.3. Vertex set;
            3.4. Edge set;
            3.5. Referer set;
            3.6. Final set;
    Noted, except for the vertex set, all other sets involving vertex are represented as the vertex alias.
    :param chain_dict:
    :return:
    """
    final_groups = aggregate_chains(chain_dict)

    # Construct the graph for each group.
    graph_dict = dict()     # Key is the grouping rule, value is the corresponding graph.
    for rule in final_groups:
        vertex_idx = 0
        url_vertex_dict = dict()        # Key is the URL, value if the corresponding vertex name.
        chain_obj_list = list()
        for node_list in final_groups[rule]:
            # A chain can be represented as [vertex_set, edge_set, ref_node, fin_node].
            # Here, we use dict to represent the vertex set.
            # For example, vertex_dict = {'v1': webpage1, 'v2': webpage2, ...}
            #              edge_list = [['v0', 'v1'], ['v1', 'v2'], ...]
            vertex_dict = dict()
            edge_list = list()
            ref_node, fin_node = None, None
            prior_vertex_name = None
            for i, node in enumerate(node_list):
                web_obj = get_webpage_params(node)
                cur_vertex_name = 'v' + str(vertex_idx)
                if web_obj[0] in url_vertex_dict:
                    cur_vertex_name = url_vertex_dict[web_obj[0]]
                else:
                    url_vertex_dict[web_obj[0]] = cur_vertex_name
                    vertex_idx += 1
                vertex_dict[cur_vertex_name] = web_obj

                if i == 0:
                    ref_node = cur_vertex_name
                elif i > 0:
                    cur_edge = [prior_vertex_name, cur_vertex_name]
                    edge_list += [cur_edge]
                if i == len(node_list) - 1:
                    fin_node = cur_vertex_name

                prior_vertex_name = cur_vertex_name

            cur_chain_obj = [vertex_dict, edge_list, ref_node, fin_node]
            chain_obj_list += [cur_chain_obj]

        # Construct the redirection graph.
        graph_chain_list = list()       # Distinct chain set (only consider the edge here).
        graph_vertex_dict = dict()      # Vertex set.
        graph_edge_list = list()        # Edge set.
        graph_referer_set = set()       # Referer set.
        graph_final_set = set()         # Final set.
        for cur_chain in chain_obj_list:
            graph_vertex_dict.update(cur_chain[0])
            chain_node_list = [cur_chain[1][0][0]]     # Initialize with the first node in the first edge.
            for edge in cur_chain[1]:
                if edge not in graph_edge_list:
                    graph_edge_list += [edge]
                chain_node_list += [edge[1]]
            graph_chain_list += [chain_node_list]
            graph_referer_set.add(cur_chain[2])
            graph_final_set.add(cur_chain[3])

        cur_graph = [rule, graph_chain_list, graph_vertex_dict, graph_edge_list, graph_referer_set, graph_final_set]
        graph_dict[rule] = cur_graph

    pprint(graph_dict)

    return graph_dict


if __name__ == '__main__':
    chain_dict = load_redirection_chains(None, 'malicious')
    construct_redirection_graph(chain_dict)
