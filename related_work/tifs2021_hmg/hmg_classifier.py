# -*-coding: utf-8 -*-

"""
@author: zyw
@file  : hmg_classifier.py
@date  : 2024/1/18
"""


import os
import numpy as np
import random
import matplotlib.pyplot as plt

from pprint import pprint
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_curve, auc


def load_data(file_path: str) -> list:
    """
    Given the file path of the labeled samples, load the sample features.
    :param file_path:
    :return:
    """
    feature_list = list()
    with open(file_path, 'r', encoding='utf-8') as fr:
        for line in fr:
            line = line.strip('\n').split('\t')
            sample, label = line[0], line[1]
            features = [float(i) for i in line[2:]]
            feature_list += [features]
    return feature_list


def construct_train_test_data(m_split_ratio: float = 0.9, b_split_ratio: float = 0.9) -> (list, list, list, list):
    """
    Load sample data from the built malicious and benign sample files.
    Split the data into training set and test set.
    :param m_split_ratio: Split ratio of malicious samples.
    :param b_split_ratio: Split ratio of benign samples.
    :return:
    """
    m_sample_file = r'./data/hmg_malicious_samples.txt'
    b_sample_file = r'./data/hmg_benign_samples.txt'
    print('Loading malicious samples [%s] ...' % m_sample_file)
    m_feature_list = load_data(m_sample_file)
    print('Loading benign samples [%s] ...' % b_sample_file)
    b_feature_list = load_data(b_sample_file)
    m_label_list = [1] * len(m_feature_list)
    b_label_list = [0] * len(b_feature_list)

    m_feature_list = np.array(m_feature_list)
    b_feature_list = np.array(b_feature_list)
    m_label_list = np.array(m_label_list)
    b_label_list = np.array(b_label_list)

    # Shuffle the samples.
    np.random.seed(20)
    m_shuffle_indices = np.random.permutation(np.arange(len(m_feature_list)))
    b_shuffle_indices = np.random.permutation(np.arange(len(b_feature_list)))
    m_shuffled_features = m_feature_list[m_shuffle_indices]
    m_shuffled_labels = m_label_list[m_shuffle_indices]
    b_shuffled_features = b_feature_list[b_shuffle_indices]
    b_shuffled_labels = b_label_list[b_shuffle_indices]

    m_split_idx = int(m_split_ratio * len(m_shuffled_features))
    b_split_idx = int(b_split_ratio * len(b_shuffled_features))

    print('Training set:')
    print('    - Malicious: %d' % m_split_idx)
    print('    - Benign: %d' % b_split_idx)
    print('Test set:')
    print('    Malicious: %d' % (len(m_shuffled_features) - m_split_idx))
    print('    Benign: %d' % (len(b_shuffled_features) - b_split_idx))

    x_train_list = np.concatenate((m_shuffled_features[:m_split_idx], b_shuffled_features[:b_split_idx]), axis=0)
    y_train_list = np.concatenate((m_shuffled_labels[:m_split_idx], b_shuffled_labels[:b_split_idx]), axis=0)
    x_test_list = np.concatenate((m_shuffled_features[m_split_idx:], b_shuffled_features[b_split_idx:]), axis=0)
    y_test_list = np.concatenate((m_shuffled_labels[m_split_idx:], b_shuffled_labels[b_split_idx:]), axis=0)

    return x_train_list, y_train_list, x_test_list, y_test_list


def hmg_model() -> None:
    """
    The TIFS-2021 work employs the random forest model.
    :return:
    """
    x_train, y_train, x_test, y_test = construct_train_test_data()

    np.random.seed(20)
    train_shuffle_indices = np.random.permutation(np.arange(len(x_train)))
    test_shuffle_indices = np.random.permutation(np.arange(len(x_test)))
    x_train, y_train = x_train[train_shuffle_indices], y_train[train_shuffle_indices]
    x_test, y_test = x_test[test_shuffle_indices], y_test[test_shuffle_indices]

    # Train the random forest model.
    rf_clf = RandomForestClassifier()
    rf_clf.fit(x_train, y_train)
    rf_y_predict = rf_clf.predict(x_test)
    rf_acc = np.mean(y_test == rf_y_predict)
    y_predict_prob = rf_clf.predict_proba(x_test)
    fp, tp, threshold = roc_curve(y_test, y_predict_prob[:, 1], pos_label=1)

    print('HMG ACC:', rf_acc)
    print('HMG AUC:', auc(fp, tp))

    # Plot the ROC curve.
    plt.plot(fp, tp, label='HMG')
    plt.tick_params(labelsize=20)
    plt.xlabel('False Positive Rate', fontdict={'size': 15})
    plt.ylabel('True Positive Rate', fontdict={'size': 15})
    plt.legend(loc='lower right', fontsize='xx-large')
    plt.grid(color='#A9A9A9', linewidth=0.5, linestyle='--')
    plt.tight_layout()
    plt.show()

    hmg_roc_file = r'./data/hmg_roc.txt'
    roc_str = ''
    for i in range(fp.shape[0]):
        temp_str = str(fp[i]) + '\t' + str(tp[i]) + '\t' + str(threshold[i]) + '\n'
        roc_str += temp_str
    with open(hmg_roc_file, 'w') as fw:
        fw.write(roc_str)


if __name__ == "__main__":
    hmg_model()
