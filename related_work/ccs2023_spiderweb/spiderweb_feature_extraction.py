# -*-coding: utf-8 -*-

"""
@author: zyw
@file  : spiderweb_feature_extraction.py
@date  : 2024/4/4

This is the reproduction of the CCS-2013 paper titled
    'Shady Paths: Leveraging Surfing Crowds to Detect Malicious Web Pages'.
This work constructs 5 types of feature, namely Client Features, Referer Features, Landing Page Features,
    Final Page Features, and Redirection Graph Features, totally 28 features.

Note:
    Ignore the client features and country-related features.

Steps:
    1. Recover the redirection chain of each sample;
    2. Build the final URL set;
    3. Aggregate the redirection chain that share the same (or similar) final URL to form the graph;
    4. Extract the features for each redirection graph.
"""


import os

from urllib import parse
from typing import Optional
from publicsuffixlist import PublicSuffixList
from spiderweb_dataset import load_redirection_chains, construct_redirection_graph


psl = PublicSuffixList(accept_unknown=False, only_icann=True)


def extract_tld_page_set(graph_dict: dict) -> tuple[dict, dict]:
    """
    Count the distinct TLD, distinct page name and the corresponding frequency of the final node in the entire graphs.
    :param graph_dict:
    :return: tld_dict, page_dict
    """
    tld_dict = dict()
    page_dict = dict()
    for rule in graph_dict:
        final_set = graph_dict[rule][5]
        vertex_dict = graph_dict[rule][2]
        for vertex in final_set:
            tld = vertex_dict[vertex][3]
            page = vertex_dict[vertex][4]
            if tld in tld_dict:
                tld_dict[tld] += 1
            else:
                tld_dict[tld] = 1
            if page in page_dict:
                page_dict[page] += 1
            else:
                page_dict[page] = 1
    return tld_dict, page_dict


def extract_referer_features(tar_graph: list) -> list:
    """
    Extract the following referer features:
        1. Distinct Referer URLs ratio;
        2. Referer Parameter Ratio;
        3. Referer with Parameters Ratio.
    :param tar_graph:
    :return:
    """
    distinct_chain_cnt = len(tar_graph[1])
    referer_set = tar_graph[4]
    f1 = len(referer_set) / distinct_chain_cnt

    referer_param_set = set()
    has_param_cnt = 0
    for referer in referer_set:
        param = tar_graph[2][referer][5]
        if param:
            referer_param_set.add(param)
            has_param_cnt += 1
    f2 = len(referer_param_set) / distinct_chain_cnt
    f3 = has_param_cnt / distinct_chain_cnt

    return [f1, f2, f3]


def extract_final_page_features(tar_graph: list) -> list:
    """
    Extract the following final page features:
        1. Distinct Final Pager URLs ratio;
        2. Final Page Parameter Ratio;
        3. Final Page with Parameters Ratio;
        4. TLD;
        5. Page name;
        6. Domain is an IP.
    :param tar_graph:
    :return:
    """
    distinct_chain_cnt = len(tar_graph[1])
    final_set = tar_graph[5]
    f1 = len(final_set) / distinct_chain_cnt

    final_param_set = set()
    has_param_cnt = 0
    tld_set = set()
    page_name_set = set()
    is_ip_format = False
    for final in final_set:
        param = tar_graph[2][final][5]
        if param:
            final_param_set.add(param)
            has_param_cnt += 1

        tld = tar_graph[2][final][3]
        tld_set.add(tld)
        if not tld:
            is_ip_format = True

        page_name = tar_graph[2][final][4]
        page_name_set.add(page_name)

    f2 = len(final_param_set) / distinct_chain_cnt
    f3 = has_param_cnt / distinct_chain_cnt
    f4 = list(tld_set)
    f5 = list(page_name_set)
    f6 = int(is_ip_format)

    return [f1, f2, f3, f4, f5, f6]


def extract_graph_features(tar_graph: list) -> list:
    """
    Extract the following redirection graph features:
        1. Maximum Chain Length;
        2. Minimum Chain Length;
        3. Intra-domain Step;
        4. Graph has Hub 30%;
        5. Graph has Hub 80%;
        6. Self-loop on the Final Page.
    :param tar_graph:
    :return:
    """
    max_chain_len = len(tar_graph[1][0])
    min_chain_len = len(tar_graph[1][0])
    has_intra_dm_step = False
    has_self_loop = False
    for chain in tar_graph[1]:
        if len(chain) > max_chain_len:
            max_chain_len = len(chain)
        if len(chain) < min_chain_len:
            min_chain_len = len(chain)

        # Check the intra-domain redirection.
        if has_intra_dm_step and has_self_loop:
            continue
        for i in range(1, len(chain)):
            if not has_intra_dm_step and tar_graph[2][chain[i]][1] == tar_graph[2][chain[i-1]][1]:
                has_intra_dm_step = True
            if not has_self_loop and tar_graph[2][chain[i]][0] == tar_graph[2][chain[i-1]][0]:
                has_self_loop = True

    # Check the 30% and 80% hub.
    # Note that, hub should be the intermediary or the start node, not the end node.
    has_hub_30, has_hub_80 = False, False
    if len(tar_graph[1]) >= 5:      # Filter the small-scale graph.
        vertex_freq_dict = dict()
        for vertex in tar_graph[2]:
            if vertex in tar_graph[5]:      # Ignore the final node.
                continue
            for chain in tar_graph[1]:
                if vertex in chain:
                    if vertex in vertex_freq_dict:
                        vertex_freq_dict[vertex] += 1
                    else:
                        vertex_freq_dict[vertex] = 1
        for vertex in vertex_freq_dict:
            if has_hub_80 and has_hub_30:
                break
            if not has_hub_80 and vertex_freq_dict[vertex] / len(tar_graph[1]) >= 0.8:
                has_hub_80 = True
                has_hub_30 = True
            elif not has_hub_30 and vertex_freq_dict[vertex] / len(tar_graph[1]) >= 0.3:
                has_hub_30 = True

    return [max_chain_len, min_chain_len, int(has_intra_dm_step), int(has_hub_30), int(has_hub_80), int(has_self_loop)]


def get_sample_features(tar_graph: list) -> list:
    """
    Extract the referer features, the final page features, and the redirection graph features of the given sample.
    :param tar_graph:
    :return:
    """
    referer_feature_list = extract_referer_features(tar_graph)
    final_page_feature_list = extract_final_page_features(tar_graph)
    graph_feature_list = extract_graph_features(tar_graph)

    total_feature_list = referer_feature_list + final_page_feature_list + graph_feature_list
    return total_feature_list


def extract_features() -> tuple[list, list]:
    """
    Get the features of malicious and benign redirection graph samples.
    :return: malicious_sample_features, benign_sample_features
    """
    # Used to modify the TLD and page name features.
    malicious_chain_dict = load_redirection_chains(None, 'malicious')
    malicious_graph_dict = construct_redirection_graph(malicious_chain_dict)
    benign_chain_dict = load_redirection_chains(None, 'benign')
    benign_graph_dict = construct_redirection_graph(benign_chain_dict)
    m_tld_dict, m_page_dict = extract_tld_page_set(malicious_graph_dict)
    b_tld_dict, b_page_dict = extract_tld_page_set(benign_graph_dict)
    tld_dict, page_dict = dict(), dict()
    total_tld_freq, total_page_freq = 0, 0
    for tld in m_tld_dict:
        if tld in tld_dict:
            tld_dict[tld] += m_tld_dict[tld]
        else:
            tld_dict[tld] = m_tld_dict[tld]
        total_tld_freq += m_tld_dict[tld]
    for tld in b_tld_dict:
        if tld in tld_dict:
            tld_dict[tld] += b_tld_dict[tld]
        else:
            tld_dict[tld] = b_tld_dict[tld]
        total_tld_freq += b_tld_dict[tld]
    for page in m_page_dict:
        if page in page_dict:
            page_dict[page] += m_page_dict[page]
        else:
            page_dict[page] = m_page_dict[page]
        total_page_freq += m_page_dict[page]
    for page in b_page_dict:
        if page in page_dict:
            page_dict[page] += b_page_dict[page]
        else:
            page_dict[page] = b_page_dict[page]
        total_page_freq += b_page_dict[page]

    m_sample_features_list, b_sample_features_list = list(), list()

    for m_rule in malicious_graph_dict:
        cur_m_features = get_sample_features(malicious_graph_dict[m_rule])
        # Modify the TLD (f7) and page name (f8) features of malicious samples.
        f7 = sum([tld_dict[tld] for tld in cur_m_features[6]]) / total_tld_freq
        f8 = sum([page_dict[page] for page in cur_m_features[7]]) / total_page_freq
        cur_m_features[6] = f7
        cur_m_features[7] = f8
        m_sample_features_list += [cur_m_features]
    for b_rule in benign_graph_dict:
        cur_b_features = get_sample_features(benign_graph_dict[b_rule])
        # Modify the TLD (f6) and page name (f7) features of benign samples.
        f7 = sum([tld_dict[tld] for tld in cur_b_features[6]]) / total_tld_freq
        f8 = sum([page_dict[page] for page in cur_b_features[7]]) / total_page_freq
        cur_b_features[6] = f7
        cur_b_features[7] = f8
        b_sample_features_list += [cur_b_features]

    return m_sample_features_list, b_sample_features_list


if __name__ == '__main__':
    extract_features()
