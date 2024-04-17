# -*-coding: utf-8 -*-

"""
@author: zyw
@file  : hmg_feature_extraction.py
@date  : 2024/1/18

This is the reproduction of the TIFS-2021 paper titled 'An Exploit Kits Detection Approach Based on HTTP Message Graph'.
This work constructs 4 types of feature, namely Node Property, Edge Property, Graph Property, and Centrality,
    totally 24 features.

Steps:
    1. Recover the request-response pairs from performance logs;
    2. Build node set, where each node represents a request-response pair;
    3. Build edge set, where each edge represents a request relationship between two nodes;
    4. Build the HMG graph based on 'networkx' 3rd library;
    5. Extract the corresponding features.
"""


import os
import json
import networkx as nx

from urllib import parse
from publicsuffixlist import PublicSuffixList


def extract_request_response_pairs(log_path: str) -> list:
    """
    Extract request-response pairs from the performance log.
    Only consider the 'Network.requestWillBeSent' and 'Network.responseReceived' entries here.
    Match the request and response entries based on the requestID field.
    :param log_path:
    :return:
    """
    target_method_set = {'Network.requestWillBeSent', 'Network.responseReceived'}
    request_id_dict = dict()        # Key is requestId, value is the entry list.

    with open(log_path, 'r', encoding='utf-8') as fr:
        for i, line in enumerate(fr):
            line = line.strip('\n')
            line_entry_dict = eval(line)
            method_dict = json.loads(line_entry_dict['message'])
            message_dict = method_dict['message']

            if message_dict['method'] not in target_method_set:
                continue

            message_dict['timestamp'] = line_entry_dict['timestamp']
            cur_id = message_dict['params']['requestId']
            if cur_id in request_id_dict:
                request_id_dict[cur_id] += [message_dict]
            else:
                request_id_dict[cur_id] = [message_dict]

    items_list = list()
    for cur_id in request_id_dict:
        items_list += [request_id_dict[cur_id][:]]

    return items_list


def construct_nodes(items_list: list) -> list:
    """
    Given the request items, convert them into graph nodes.
    Each node is represented as: N= [SN, URL, Referer, Host, Method, Location, StatusCode].
        - SN is the sequence number indicated by the timestamp order;
        - Location only exists when 30X redirection occurs.
    Arrange the nodes in ascending order based on the SN field.
    Note that, an item may contain different types of elements.
        1. Mostly, a request entry and a response entry;
        2. Only a request entry, which is always caused by insufficient waiting time.
        3. Many request entries, which is caused by repeatedly requesting the same resources or 30X redirection.
    :param items_list:
    :return:
    """
    psl = PublicSuffixList(accept_unknown=False, only_icann=True)

    node_list = list()
    node_sn = 0
    for items in items_list:
        # Only a request entry. In this case, we should manually complement the StatusCode field.
        # Filter the case with only 'responseReceived' entry.
        if len(items) == 1:
            if items[0]['method'] == 'Network.responseReceived':
                continue
            request = items[0]
            timestamp = request['timestamp']
            url = request['params']['request']['url']
            host = parse.urlparse(url).netloc
            # Filter the invalid domains.
            e2ld = psl.privatesuffix(host)
            if not host or not e2ld:
                continue
            method = request['params']['request']['method']
            referer = None
            if 'Referer' in request['params']['request']['headers']:
                referer = request['params']['request']['headers']['Referer']
            location = None
            status_code = 200

            cur_node = [node_sn, url, referer, host, method, location, status_code]
            node_list += [cur_node]
            node_sn += 1
        # No matter how many entries are in the items, process them in the same form.
        # Specifically, directly extracting the corresponding field from the followup entry.
        #   1. For the StatusCode field, we should determine whether the next entry is 'responseReceived';
        #   2. For the Location field, we should determine whether the next entry is 'redirectResponse';
        #   3. For the last request entry, the StatusCode is set to 200 by default if there is no response after it.
        else:
            for i, item in enumerate(items):
                if item['method'] == 'Network.requestWillBeSent':
                    request = item
                    timestamp = request['timestamp']
                    url = request['params']['request']['url']
                    host = parse.urlparse(url).netloc
                    e2ld = psl.privatesuffix(host)
                    if not host or not e2ld:
                        continue
                    method = request['params']['request']['method']
                    referer = None
                    if 'Referer' in request['params']['request']['headers']:
                        referer = request['params']['request']['headers']['Referer']
                    location = None
                    status_code = 200

                    # Modify the corresponding field based on the followup entry.
                    # Check whether the current entry is last one in the list.
                    if i + 1 < len(items):
                        # The next entry is the 'responseReceived' entry.
                        if items[i + 1]['method'] == 'Network.responseReceived':
                            response = items[i + 1]
                            status_code = response['params']['response']['status']
                            i += 2
                            cur_node = [node_sn, url, referer, host, method, location, status_code]
                            node_list += [cur_node]
                            node_sn += 1
                            continue
                        # The next entry is the 'requestWillBeSent' entry.
                        else:
                            # Whether the next entry is a 'redirectResponse' request.
                            if 'redirectResponse' in items[i + 1]['params']:
                                redirect_request = items[i + 1]
                                # The field maybe 'Location' or 'location'.
                                if 'location' in redirect_request['params']['redirectResponse']['headers']:
                                    location = redirect_request['params']['redirectResponse']['headers']['location']
                                elif 'Location' in redirect_request['params']['redirectResponse']['headers']:
                                    location = redirect_request['params']['redirectResponse']['headers']['Location']
                                elif 'LOCATION' in redirect_request['params']['redirectResponse']['headers']:
                                    location = redirect_request['params']['redirectResponse']['headers']['LOCATION']
                                location = parse.urljoin(url, location)
                                status_code = redirect_request['params']['redirectResponse']['status']

                    cur_node = [node_sn, url, referer, host, method, location, status_code]
                    node_list += [cur_node]
                    node_sn += 1

    return node_list


def construct_edges(node_list: list) -> list:
    """
    Given the node list, construct the edges based on the 'Referer' and 'Location' fields of nodes.
    Each edge is represented as: E = [N_s, N_d, Type].
        - N_s and N_d are the origin and end of the edge, respectively.
        - Two types, redirection and referer, determined by the corresponding field.
        - Use SN to indicate the corresponding node, e.g., [2, 3, Referer] means a Referer edge pointing from 2 to 3.
        - Edge must point from the node with small SN to the node with big SN.
    :param node_list:
    :return:
    """
    # Construct a dictionary to speed up the lookup.
    url_nodes_dict = dict()     # Some nodes may have the same URL, namely requesting the same resource.
    for node in node_list:
        url = node[1]
        if url in url_nodes_dict:
            url_nodes_dict[url] += [node]
        else:
            url_nodes_dict[url] = [node]

    edge_list = list()
    # Find parent nodes.
    for node in node_list:
        # Check 'Location' field.
        location = node[-2]
        if location and location in url_nodes_dict:
            son_node = url_nodes_dict[location][0]
            if node[0] < son_node[0]:       # Make Sure the SN order.
                location_edge = [node[0], son_node[0], 'location']
                edge_list += [location_edge]
        # Check 'Referer' field.
        referer = node[2]
        if referer and referer in url_nodes_dict:
            for parent_node in url_nodes_dict[referer]:
                if parent_node[0] < node[0]:        # Make Sure the SN order.
                    referer_edge = [parent_node[0], node[0], 'referer']
                    edge_list += [referer_edge]
    return edge_list


def construct_graph(node_list: list, edge_list: list) -> nx.DiGraph:
    """
    Given the node list and edge list, construct the HMG based on the networkx library.
    :param node_list:
    :param edge_list:
    :return:
    """
    hmg = nx.DiGraph()
    for node in node_list:
        hmg.add_node(node[0],
                     url=node[1], referer=node[2], host=node[3],
                     method=node[4], location=node[5], status_code=node[6])
    for edge in edge_list:
        hmg.add_edge(edge[0], edge[1], edge_type=edge[2])

    return hmg


def get_node_features(node_list: list) -> list:
    """
    Given the node list of the HMG, extracting the node property features.
    Five node property features:
        1. F1: node count;
        2. F2: 40X status node ratio;
        3. F3: Referer node ratio;
        4. F4: IP host ratio;
        5. F5: Post method node ratio.
    :param node_list:
    :return:
    """
    psl = PublicSuffixList(accept_unknown=False, only_icann=True)

    # F1
    node_cnt = len(node_list)

    status_40x_cnt = 0
    referer_cnt = 0
    ip_cnt = 0
    post_cnt = 0
    for node in node_list:
        # F2
        status = node[-1]
        if int(status / 10) == 40:
            status_40x_cnt += 1
        # F3
        referer = node[2]
        if referer:
            referer_cnt += 1
        # F4
        host = node[3]
        e2ld = psl.privatesuffix(host)
        if not e2ld and len(host.split('.')) == 4:      # Check whether the hostname is an IP address.
            ip_cnt += 1
        # F5
        method = node[4]
        if method == 'POST':
            post_cnt += 1
    status_40x_ratio = status_40x_cnt / node_cnt
    referer_ratio = referer_cnt / node_cnt
    ip_ratio = ip_cnt / node_cnt
    post_ratio = post_cnt / node_cnt

    return [node_cnt, status_40x_ratio, referer_ratio, ip_ratio, post_ratio]


def get_edge_features(node_list: list, edge_list: list) -> list:
    """
    Given the node list and edge list, extract the edge property features.
    Three edge features:
        1. F1: The number of 30X redirection edges;
        2. F2: The number of 30X redirection edges that connecting two nodes with different domains;
        3. F3: Length of the longest 30X redirection chain.
    :param node_list:
    :param edge_list:
    :return:
    """
    redirect_edge_list = list()
    involved_sn_set = set()
    for edge in edge_list:
        if edge[-1] == 'location':
            redirect_edge_list += [edge]
            involved_sn_set.add(edge[0])
            involved_sn_set.add(edge[1])
    sn_node_dict = dict()
    for node in node_list:
        sn = node[0]
        if sn in involved_sn_set:
            sn_node_dict[sn] = node[:]
            involved_sn_set.remove(sn)
        if not len(involved_sn_set):
            break

    # Speed up the lookup of redirection path.
    start_sn_dict = dict()      # key is start SN of and edge, value is the edge.
    for edge in redirect_edge_list:
        start_sn_dict[edge[0]] = edge[:]

    # F1
    redirect_cnt = len(redirect_edge_list)

    # F2, F3
    cross_domain_cnt = 0
    max_path_len = 0
    for edge in redirect_edge_list:
        # F2
        sn1, sn2 = edge[0], edge[1]
        node1, node2 = sn_node_dict[sn1], sn_node_dict[sn2]
        if node1[3] != node2[3]:
            cross_domain_cnt += 1
        # F3
        path_len = 1
        while sn1 in start_sn_dict:
            path_len += 1
            sn1 = start_sn_dict[sn1][1]
        max_path_len = max(path_len, max_path_len)

    return [redirect_cnt, cross_domain_cnt, max_path_len]


def get_graph_features(node_list: list, edge_list: list, hmg: nx.DiGraph) -> list:
    """
    Given the constructed directed graph HMG, extract the following three features:
        1. F1: Length of the longest path in HMG;
        2. F2: Number of the connected components in HMG;
        3. F3: Ratio of the isolated nodes in HMG.
    Here, employ the 3rd party Python library 'networkx' to construct the directed graph.
    :param node_list:
    :param edge_list:
    :param hmg:
    :return:
    """
    for node in node_list:
        hmg.add_node(node[0],
                     url=node[1], referer=node[2], host=node[3],
                     method=node[4], location=node[5], status_code=node[6])
    for edge in edge_list:
        hmg.add_edge(edge[0], edge[1], edge_type=edge[2])

    # F1
    longest_path_len = nx.dag_longest_path_length(hmg)

    # F2
    component_cnt = nx.number_weakly_connected_components(hmg)

    # # F3
    isolate_cnt = nx.number_of_isolates(hmg)
    isolate_ratio = isolate_cnt / len(node_list)

    return [longest_path_len, component_cnt, isolate_ratio]


def get_centrality_features(hmg: nx.DiGraph) -> list:
    """
    Given the constructed directed graph HMG, extracting the 13 centrality features.
    Centrality features focus on the MPR (max page rank) and MDC (max degree centrality) nodes.
        1. F1: Sequence order of MPR node;
        2. F2: The ratio of nodes with the same domain as MPR node;
        3. F3: URL length of MPR node;
        4. F4: URL path depth, of the MPR node;
        5. F5: URL query length of the MPR node;
        6. F6: Parameter number of the URL query field of the MPR node;
        7. F7: Max Pagerank value of HMG;
        8. F8: Max degree centrality of MHG;
        9. F9: Sequence order the MDC node;
        10. F10: The ratio of nodes with the same domain as MDC node;
        11. F11: Closeness centrality of MDC node;
        12. F12: Max betweenness centrality of MHG;
        13. F13: The number of nodes with non-zero betweenness centrality.
    :param hmg:
    :return:
    """
    pr_dict = nx.pagerank(hmg)
    # F1, F7
    pr_sorted_nodes = sorted(pr_dict.items(), key=lambda item: item[1], reverse=True)
    mpr_node_sn, mpr_node_pr = pr_sorted_nodes[0][0], pr_sorted_nodes[0][1]
    mpr_node = hmg.nodes[mpr_node_sn]

    # F2
    same_pr_domain_cnt = 0
    for cur_node_sn in hmg.nodes:
        if cur_node_sn != mpr_node_sn and hmg.nodes[cur_node_sn]['host'] == mpr_node['host']:
            same_pr_domain_cnt += 1
    same_pr_domain_ratio = same_pr_domain_cnt / (len(hmg.nodes) - 1)

    # F3
    mpr_url_len = len(mpr_node['url'])

    parsed_url = parse.urlparse(mpr_node['url'])
    #F4
    mpr_url_path = parsed_url.path
    mpr_url_path_depth = mpr_url_path.count('/')
    # F5
    mpr_url_query = parsed_url.query
    mpr_url_query_len = len(mpr_url_query)
    # F6
    mpr_url_query_cnt = len(mpr_url_query.split('&'))

    dc_dict = nx.degree_centrality(hmg)
    # F8, F9
    dc_sorted_nodes = sorted(dc_dict.items(), key=lambda item: item[1], reverse=True)
    mdc_node_sn, mdc_node_dc = dc_sorted_nodes[0][0], dc_sorted_nodes[0][1]
    mdc_node = hmg.nodes[mdc_node_sn]

    # F10
    same_dc_domain_cnt = 0
    for cur_node_sn in hmg.nodes:
        if cur_node_sn != mdc_node_sn and hmg.nodes[cur_node_sn]['host'] == mdc_node['host']:
            same_dc_domain_cnt += 1
    same_dc_domain_ratio = same_dc_domain_cnt / (len(hmg.nodes) - 1)

    # F11
    closeness_dict = nx.closeness_centrality(hmg)
    mdc_closeness = closeness_dict[mdc_node_sn]

    # F12
    betweenness_dict = nx.betweenness_centrality(hmg)
    max_betweenness = sorted(betweenness_dict.items(), key=lambda item: item[1], reverse=True)[0][1]
    # F13
    nonzero_betweenness_cnt = len([item for item in betweenness_dict.items() if item[1] > 0])

    return [mpr_node_sn, same_pr_domain_ratio, mpr_url_len, mpr_url_path_depth, mpr_url_query_len,
            mpr_url_query_cnt, mpr_node_pr, mdc_node_dc, mdc_node_sn, same_dc_domain_ratio,
            mdc_closeness, max_betweenness, nonzero_betweenness_cnt]


def get_hmg_features(node_list: list, edge_list: list, hmg: nx.DiGraph) -> list:
    """
    Gathering the total 24 features, including node features, edge features, graph features, and centrality features.
    :param node_list:
    :param edge_list:
    :param hmg:
    :return:
    """
    node_features = get_node_features(node_list)
    edge_features = get_edge_features(node_list, edge_list)
    graph_features = get_graph_features(node_list, edge_list, hmg)
    centrality_features = get_centrality_features(hmg)
    hmg_features = node_features + edge_features + graph_features + centrality_features

    return hmg_features


if __name__ == "__main__":
    sample_dir = os.path.abspath('../test_samples')
    for sample in os.listdir(sample_dir):
        sample_path = os.path.join(sample_dir, sample)
        log_path = os.path.join(sample_path, 'performance_log.txt')
        pair_list = extract_request_response_pairs(log_path)
        node_list = construct_nodes(pair_list)
        edge_list = construct_edges(node_list)
        hmg = construct_graph(node_list, edge_list)
        get_hmg_features(node_list, edge_list, hmg)
