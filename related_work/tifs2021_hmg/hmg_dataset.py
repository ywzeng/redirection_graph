# -*-coding: utf-8 -*-

"""
@author: zyw
@file  : hmg_dataset.py
@date  : 2024/1/18
"""

import os
import hmg_feature_extraction as hmg_fe


def collect_samples() -> (list, list):
    """
    Collect candidate samples and the corresponding saved path.
    :return:
    """
    file_source_dict = dict()
    file_source_dict['zeng_1'] = r'E:\prior_redirection_samples\zengyuwei\tag_info'
    file_source_dict['zeng_2'] = r'E:\prior_redirection_samples\zengyuwei\tag_info_2'
    file_source_dict['zeng_temp'] = r'E:\prior_redirection_samples\zengyuwei\tag_info_temp'
    file_source_dict['liang_1'] = r'E:\prior_redirection_samples\liangzhizhou\tag_info'
    file_source_dict['liang_2'] = r'E:\prior_redirection_samples\liangzhizhou\tag_info_2'
    file_source_dict['yan_1'] = r'E:\prior_redirection_samples\yandingkui\tag_info'
    file_source_dict['yan_2'] = r'E:\prior_redirection_samples\yandingkui\tag_info_2'
    file_source_dict['vmware_1'] = r'E:\prior_redirection_samples\vmware\tag_info'
    file_source_dict['vmware_2'] = r'E:\prior_redirection_samples\vmware\tag_info_2'
    file_source_dict['aliyun_1'] = r'E:\prior_redirection_samples\aliyun\tag_info'
    file_source_dict['aliyun_2'] = r'E:\prior_redirection_samples\aliyun\tag_info_2'
    file_source_dict['aliyun_3'] = r'E:\prior_redirection_samples\aliyun\tag_info_3'

    basic_malicious_file = r'../data/malicious_entries.txt'
    basic_benign_file = r'../data/benign_entries.txt'
    # basic_flux_file = r'../data/flux_entries.txt'

    malicious_sample_path_list = list()
    with open(basic_malicious_file, 'r', encoding='utf-8') as fr:
        for line in fr:
            line = line.strip('\n').split('\t')
            domain, source = line[0], line[2]
            sample_path = os.path.join(file_source_dict[source], domain)
            sample = domain + ':' + source
            malicious_sample_path_list += [(sample, sample_path)]

    benign_sample_path_list = list()
    with open(basic_benign_file, 'r', encoding='utf-8') as fr:
        for line in fr:
            line = line.strip('\n').split('\t')
            domain, source = line[0], line[2]
            sample_path = os.path.join(file_source_dict[source], domain)
            sample = domain + ':' + source
            benign_sample_path_list += [(sample, sample_path)]

    # flux_sample_path_dict = dict()
    # with open(basic_flux_file, 'r', encoding='utf-8') as fr:
    #     for line in fr:
    #         line = line.strip('\n').split('\t')
    #         domain, source = line[0], line[1]
    #         sample_path = os.path.join(file_source_dict[source], domain)
    #         sample = domain + ':' + source
    #         flux_sample_path_dict[sample] = sample_path

    return malicious_sample_path_list, benign_sample_path_list


def dump_sample_features(sample_path_list: list, saved_file: str, label: str) -> int:
    """
    Given the samples, extracting the HMG features based on the corresponding performance logs.
    :param sample_path_list: [[sample_name, sample_path], ...]
    :param saved_file:
    :param label:
    :return: The number of valid saved samples.
    """
    item_list = list()
    for i, sample_item in enumerate(sample_path_list):
        log_path = os.path.join(sample_item[1], 'performance_log.txt')
        pair_list = hmg_fe.extract_request_response_pairs(log_path)
        node_list = hmg_fe.construct_nodes(pair_list)
        if len(node_list) <= 1:
            continue
        edge_list = hmg_fe.construct_edges(node_list)
        hmg = hmg_fe.construct_graph(node_list, edge_list)
        feature_list = hmg_fe.get_hmg_features(node_list, edge_list, hmg)
        # [sample, label, feature_1, feature_2, ..., feature_n]
        item = [sample_item[0], label] + feature_list
        item_list += [item]
        print(item)

    # Save the sample features.
    saved_str = ''
    for item in item_list:
        item_str = '\t'.join([str(i) for i in item]) + '\n'
        saved_str += item_str
    with open(saved_file, 'w', encoding='utf-8') as fw:
        fw.write(saved_str)

    return len(item_list)


if __name__ == "__main__":
    m_sample_path_list, b_sample_path_list = collect_samples()
    m_saved_file = os.path.join(os.path.abspath('./data'), 'hmg_malicious_samples.txt')
    b_saved_file = os.path.join(os.path.abspath('./data'), 'hmg_benign_samples.txt')
    dump_sample_features(m_sample_path_list, m_saved_file, 'malicious')
    dump_sample_features(b_sample_path_list, b_saved_file, 'benign')

