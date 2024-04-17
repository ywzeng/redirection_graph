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
    pass


def extract_final_page_features(tar_graph: list) -> list:
    """
    Extract the following final page features:
        1. Distinct Final Pager URLs ratio;
        2. Final Page Parameter Ratio;
        3. TLD;
        4. Page name;
        5. Domain is an IP.
    :param tar_graph:
    :return:
    """
    pass


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
    pass


def extract_target_sample_features(tar_graph: list) -> list:
    """
    Extract the referer features, the final page features, and the redirection graph features of the given sample.
    :param tar_graph:
    :return:
    """
    pass


def extract_features() -> tuple[list, list]:
    """
    Get the features of malicious and benign redirection graph samples.
    :return: malicious_sample_features, benign_sample_features
    """
    pass



if __name__ == '__main__':
    pass
