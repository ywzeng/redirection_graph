# -*-coding: utf-8 -*-

"""
@author: zyw
@file  : info_extraction.py
@date  : 2024/1/23

This script focuses on extracting the redirection-related info from the corresponding performance log.
In the construction of redirection tree, we should notice request relationship between the recovered nodes.
Identify different web session based on the request ID.
Note that, the URLs (and the corresponding logged entries) are sometimes not requested in time sequence.
"""


import json
import os.path
import time
import requests
import networkx as nx

from typing import Optional
from pprint import pprint
from lxml import etree
from urllib import parse
from datetime import datetime
from publicsuffixlist import PublicSuffixList
from general_funcs import get_valid_url, url_cmp
from redirection_tree import Node, RedirectionTree


def extract_target_entries(domain_sample: str, sample_dir: str, tar_method_idx_list: Optional[list] = None) -> list:
    """
    Extract the URL request-related entries from the performance log of the given sample.
    Here, we focus on the following seven entry methods. Values in the 3rd argument are the same with following indexes.
        0. Network.requestWillBeSent -> corresponds to HTTP request;
        1. Network.responseReceived -> corresponds to HTTP response;
        2.1 Page.frameAttached -> corresponds to the attachment of frames;
        2.2 Page.frameDetached -> corresponds to the detachment of frames;
        3.1. Page.frameScheduledNavigation -> corresponds to the navigation of frame (before navigation);
        3.2. Page.frameRequestedNavigation -> corresponds to the navigation of the frame (after navigation);
        4. Page.navigatedWithinDocument -> corresponds to <meta> tag refresh;
        5. Page.downloadWillBegin -> corresponds to download event (always drive-by download in our crawling).
        6. Network.loadingFailed -> refers to the resource was not successfully loaded.
    Rough division:
        1). URL request-related methods: requestWillBeSent, responseReceived;
        2). Frame navigation-related methods: navigatedWithinDocument, frameAttached, frameScheduledNavigation;
        3). Download-related methods: Page.downloadWillBegin.
    Notice to filter the remaining entries of prior crawling task.
    For 'responseReceived' entries, we only focuses on the ones related to 'httpHeaderRefresh', namely the ones have 'Refresh' field.
    :param domain_sample: Used to filter the entries requested by prior crawling task as well.
    :param sample_dir:
    :param tar_method_idx_list: The index of target entry methods.
    :return:
    """
    base_method_list = ['Network.requestWillBeSent', 'Network.responseReceived',
                        'Page.frameAttached', 'Page.frameDetached', 'Network.loadingFailed',
                        'Page.navigatedWithinDocument', 'Page.frameRequestedNavigation', 'Page.downloadWillBegin',]

    tar_method_set = set(base_method_list)
    if tar_method_idx_list:
        tar_method_set = set([base_method_list[idx] for idx in tar_method_idx_list])

    # Used to filter the remaining entries left by the prior crawling task.
    start_url = 'http://' + domain_sample + '/'
    has_filtered = False

    entry_list = list()
    log_path = os.path.join(sample_dir, 'performance_log.txt')
    with open(log_path, 'r', encoding='utf-8') as fr:
        for i, line in enumerate(fr):
            line = line.strip('\n')
            line_entry_dict = eval(line)
            method_dict = json.loads(line_entry_dict['message'])
            message_dict = method_dict['message']

            # Filter the entries left by prior crawling task until find the first matched 'requestWillBeSent' entry.
            if not has_filtered:
                if message_dict['method'] != 'Network.requestWillBeSent':
                    continue
                else:
                    if message_dict['params']['request']['url'] != start_url:
                        continue
                    elif message_dict['params']['request']['url'] == start_url:
                        has_filtered = True

            # Filter the undesired entries.
            if message_dict['method'] not in tar_method_set:
                continue
            # Only gather the 'responseReceived' entries related to 'httpHeaderRefresh' redirections.
            if message_dict['method'] == 'Network.responseReceived' and 'Refresh' not in message_dict['params']['response']['headers']:
                continue
            # Chrome crash case.
            if message_dict['method'] == 'Network.requestWillBeSent' and message_dict['params']['documentURL'] == 'chrome-error://chromewebdata/':
                entry_list.clear()
                break
            # Filter the loading failed request-entries.
            if message_dict['method'] == 'Network.loadingFailed':
                failed_request_id = message_dict['params']['requestId']
                # Reverse search the failed request-entry.
                tar_idx = len(entry_list) - 1
                while tar_idx >= 0:
                    if entry_list[tar_idx]['method'] == 'Network.requestWillBeSent' and \
                            entry_list[tar_idx]['params']['requestId'] == failed_request_id:
                        break
                    tar_idx -= 1
                if tar_idx >= 0:
                    entry_list.pop(tar_idx)

            message_dict['timestamp'] = line_entry_dict['timestamp']
            entry_list += [message_dict]

    # # Sort the entries in ascending order according to the timestamp.
    # entry_list.sort(key=lambda item: item['timestamp'], reverse=False)

    return entry_list


def get_parent_info(entry_list: list) -> list:
    """
    Given the target entries, analyze the initiator info (or the so-called parent info) of each entry.
    It's really a dirty work.

    The request sources and the related entry methods are list as follows:
        1). redirectResponse: 'requestWillBeSent' ('params.redirectResponse' field);
        2). httpHeaderRefresh: 'frameScheduledNavigation' and 'frameRequestedNavigation' ('reason' field);
        3). metaTagRefresh: 'frameScheduledNavigation' and 'frameRequestedNavigation' ('reason' field);
        4). scriptInitiated: 'frameScheduledNavigation' and 'frameRequestedNavigation' ('reason' field);
        5). formSubmissionGet: 'frameScheduledNavigation' and 'frameRequestedNavigation' ('reason' field);
        6). formSubmissionPost: 'frameScheduledNavigation' and 'frameRequestedNavigation' ('reason' field);
        7). reload: 'frameScheduledNavigation' and 'frameRequestedNavigation' ('reason' field);
        8). script: 'requestWillBeSent' ('initiator.type');
        9). parser: 'requestWillBeSent' ('initiator.type');
        10). other: 'requestWillBeSent' ('initiator.type');
    For 2)-7), we focus on 'frameRequestedNavigation' instead of 'frameScheduleNavigation'.

    For each request type, we should match the corresponding parent node in different ways. List as follows:
        1). redirectResponse: directly specified in the 'params.redirectResponse.url' field;
        2). httpHeaderRefresh: match the corresponding 'Refresh' field in the prior 'responseReceived' entry;
        3)-7). metaTagRefresh - reload: match the corresponding 'params.request.url' in the prior 'requestWillBeSent' entry,
                                        and then get the parent node via the 'initiator' field;
        8). script: parent node is specified in 'Referer' field or 'initiator.url' field;
        9). parser: parent node is specified in 'Referer' field;
        10). other: parent node can only be matched via the 'Referer' field, mostly related to 'click' events.

    For iframe tags, gather 'frameAttached' and 'frameDetached' entries to identify iframe tags and their parent frames.
    Notice the loadId of each 'requestWillBeSent' entry, which is used to match the parent URL of non-Document request.
    :param entry_list:
    :return: [[request_url, resource_type, parent_url, parent_source, timestamp], ...]
    """
    parent_info_list = list()   # [[request_url, resource_type, parent_url, parent_source, timestamp, frame_id], ...]
    url_fragment_dict = dict()   # For 'requestWillBeSent' and 'navigatedWithinDocument'. {no_fragment: with_fragment}

    # Used to label the nesting relationship between iframe and its parent frame.
    # Add and remove (frame_id, parent_id) pairs when encountering 'frameAttached' and 'frameDetached', respectively.
    frame_parent_dict = dict()     # {frame_id: parent_id}. Updated when parsing 'frameAttached' and 'frameDetached'.

    # Record the newest URL of specific frame. Involving 'requestWillBeSent' and 'navigatedWithinDocument'.
    frame_url_dict = dict()     # {frame_id: document_url}
    # The attribution of each requested resource is determined by its loaderIDs.
    # The loaderID is changing with frame redirection.
    loader_url_dict = dict()  # {loader_id: frame_url (with fragment)}
    # Record the loaderID and its matched frameID.
    frame_loader_dict = dict()      # {frame_id: loader_id}

    # Record the basic info of 'frameRequestedNavigation' (or 'frameScheduledNavigation') entries.
    frame_navigate_info_list = list()

    for i, entry in enumerate(entry_list):
        # 1. Extract the frame loading-related entries ('Page.frameAttached' and 'Page.frameDetached').
        if entry['method'] == 'Page.frameAttached':
            frame_id = entry['params']['frameId']
            parent_frame_id = entry['params']['parentFrameId']
            frame_parent_dict[frame_id] = parent_frame_id
        elif entry['method'] == 'Page.frameDetached':
            frame_id = entry['params']['frameId']
            if frame_id in frame_parent_dict:
                frame_parent_dict.pop(frame_id)
            if frame_id in frame_url_dict:
                frame_url_dict.pop(frame_id)

        # 2. Extract the frame navigation-related entries ('Page.frameRequestedNavigation').
        elif entry['method'] == 'Page.frameRequestedNavigation':
            frame_id = entry['params']['frameId']
            navigate_url = entry['params']['url']
            # httpHeaderRefresh, metaTagRefresh, scriptInitiated, formSubmissionGet, formSubmissionPost, anchorClick, reload
            reason = entry['params']['reason']
            timestamp = entry['timestamp']

            navigate_info = [frame_id, navigate_url, reason, timestamp]
            frame_navigate_info_list += [navigate_info]

            # # 2.1. httpHeaderRefresh
            # if reason == 'httpHeaderRefresh':
            #     http_header_refresh_entry_list += [entry]
            # # 2.2. metaTagRefresh
            # elif reason == 'metaTagRefresh':
            #     meta_tag_refresh_entry_list += [entry]
            # # 2.3. scriptInitiated
            # elif reason == 'scriptInitiated':
            #     pass
            # # 2.4. formSubmissionGet
            # elif reason == 'formSubmissionGet':
            #
            # # 2.5. formSubmissionPost
            # elif reason == 'formSubmissionPost':
            #     pass
            # # 2.6. reload
            # elif reason == 'reload':
            #     pass
            # else:
            #     print("Another frame navigation type found: %s." % reason)

        # # 3. Extract the 'Refresh'-related response entries ('Network.responseReceived' with 'Refresh' field).
        # elif entry['method'] == 'Network.responseReceived':
        #     refresh_field = entry['params']['response']['headers']['Refresh']
        #     refresh_field = refresh_field.spit('url=')
        #     delay = refresh_field[0].split(';')[0]      # Refresh delay.
        #     refresh_url = refresh_field[1]
        #     response_url = entry['params']['response']['url']       # Indicate the page that wille be refreshed.
        #     response_refresh_entry_list += [(response_url, refresh_url)]

        # 3. Extract the URL request entries ('Network.requestWillBeSent').
        elif entry['method'] == 'Network.requestWillBeSent':
            document_url = entry['params']['documentURL']
            frame_id = entry['params']['frameId']
            loader_id = entry['params']['loaderId']
            resource_type = entry['params']['type']
            timestamp = entry['timestamp']
            request_url = entry['params']['request']['url']

            # Get initiator info.
            initiator_dict = {'type': entry['params']['initiator']['type']}
            if 'url' in entry['params']['initiator']:
                initiator_dict['url'] = entry['params']['initiator']['url']
            elif 'stack' in entry['params']['initiator']:
                call_url_list = list()
                for call_frame in entry['params']['initiator']['stack']['callFrames']:
                    cur_call_url = call_frame['url']
                    if cur_call_url and cur_call_url not in call_url_list:
                        call_url_list += [cur_call_url]
                if call_url_list:
                    initiator_dict['url'] = ';'.join(call_url_list)
                else:
                    initiator_dict['url'] = ''

            # 4.1. Process the Document type request entries.
            if resource_type == 'Document':
                # Complete the URL when 'urlFragment' exists.
                if 'urlFragment' in entry['params']['request']:
                    url_fragment_dict[request_url] = request_url + entry['params']['request']['urlFragment']
                    request_url += entry['params']['request']['urlFragment']
                else:
                    url_fragment_dict[request_url] = request_url

                # 4.1.1. Process the first request URL.
                if i == 0:
                    parent_url = ''
                    parent_source = 'root'
                    root_info = [request_url, resource_type, parent_url, parent_source, timestamp, frame_id]
                    parent_info_list += [root_info]
                # 4.1.2. Process the 30X redirection entry.
                elif 'redirectResponse' in entry['params']:
                    parent_url = entry['params']['redirectResponse']['url']
                    parent_source = 'redirectResponse'
                    # Modify the parent URL if it has fragment.
                    parent_url = url_fragment_dict[parent_url]
                    redirect_parent_info = [request_url, resource_type, parent_url, parent_source, timestamp, frame_id]
                    parent_info_list += [redirect_parent_info]
                # 4.1.3. Process the iframe-related request entries.
                elif frame_parent_dict and frame_id in frame_parent_dict:
                    parent_frame_id = frame_parent_dict[frame_id]
                    # Some iframe do not have 'src' attribute.
                    # In such cases, employ its parent frame as the parent frame of its sub-frame.
                    if parent_frame_id not in frame_url_dict:
                        parent_frame_id = frame_parent_dict[parent_frame_id]
                    if parent_frame_id not in frame_url_dict:
                        continue
                    parent_url = frame_url_dict[parent_frame_id]    # The frame URL have already modified with fragment.
                    parent_source = initiator_dict['type']
                    document_parent_info = [request_url, resource_type, parent_url, parent_source, timestamp, frame_id]
                    parent_info_list += [document_parent_info]
                # 4.1.4. Process other request types, including 'metaTagRefresh', 'httpHeaderRefresh',
                #           'scriptInitiated', 'formSubmissionGet', 'formSubmissionPost', 'reload'.
                #        Because such redirection types cannot be inferred directly from the 'requestWillBeSent' entry.
                #        Specifically, the initiator type should be extracted from the 'frameRequestedNavigation' entry.
                #        So, further modifications are left to the processing on 'frameRequestedNavigation' entry.
                #
                #        Besides, such redirections will not change the frame_id of the request entry.
                #        Therefore, we can directly assign the parent_url of related request based on the frame_id.
                else:
                    parent_url = frame_url_dict[frame_id]
                    parent_source = initiator_dict['type']
                    document_parent_info = [request_url, resource_type, parent_url, parent_source, timestamp, frame_id]
                    parent_info_list += [document_parent_info]

                # Update the frame/loader URL when encountering 'Document'-related requests.
                frame_url_dict[frame_id] = request_url      # The URL has already been modified with fragment.
                loader_url_dict[loader_id] = request_url
                # Update the matched relationship between frameID and loaderID.
                frame_loader_dict[frame_id] = loader_id

            # 4.2. Process the non-Document type request (redirectResponse) entries.
            else:
                # Check whether the entry is left by other crawling. Filter the entry if so.
                if loader_id not in loader_url_dict and frame_id not in frame_url_dict:
                    continue

                # Complete the URL when 'urlFragment' exists.
                if 'urlFragment' in entry['params']['request']:
                    request_url += entry['params']['request']['urlFragment']

                parent_url = document_url       # Initialize with documentURL.
                if loader_id in loader_url_dict:
                    parent_url = loader_url_dict[loader_id]     # The URL has been modified with fragment.
                else:
                    parent_url = frame_url_dict[frame_id]

                # 4.2.1. 'script' initiator type entries.
                if initiator_dict['type'] == 'script':
                    parent_source = 'script'
                # 4.2.2. 'parser' initiator type entries.
                elif initiator_dict['type'] == 'parser':
                    parent_source = 'parser'
                # 4.2.3. 'other' initiator type entries.
                elif initiator_dict['type'] == 'other':
                    parent_source = 'other'
                else:
                    print('Another initiator type found (%s).' % initiator_dict['type'])
                    break

                non_document_parent_info = [request_url, resource_type, parent_url, parent_source, timestamp, frame_id]
                parent_info_list += [non_document_parent_info]

        # 4. Extract the anchor-related entries ('Page.navigatedWithinDocument').
        elif entry['method'] == 'Page.navigatedWithinDocument':
            frame_id = entry['params']['frameId']
            navigate_url = entry['params']['url']
            # Ignore the entries without already existing frame_id.
            # Mostly involves <iframe> tags without 'src' attribute.
            if frame_id not in frame_url_dict:
                continue
            parent_url = frame_url_dict[frame_id]
            parent_source = 'navigatedWithinDocument'
            timestamp = entry['timestamp']

            # Update the URL fragment dict.
            navigate_url_prefix = navigate_url.split('#')[0]
            url_fragment_dict[navigate_url_prefix] = navigate_url
            # Update the document URL of the current frame.
            frame_url_dict[frame_id] = navigate_url

            # 'navigatedWithinDocument' neither changes frameID nor loaderID.
            # Update the document URL of the corresponding loader.
            loader_id = frame_loader_dict[frame_id]
            loader_url_dict[loader_id] = navigate_url

            # Update the parent info list.
            anchor_parent_info = [navigate_url, 'Document', parent_url, parent_source, timestamp, frame_id]
            parent_info_list += [anchor_parent_info]

        # 5. Extract the download-related entries ('Page.downloadWillBegin').
        elif entry['method'] == 'Page.downloadWillBegin':
            download_url = entry['params']['url']
            # Get the matching download-realted 'requestWillBeSent' entry.
            for j in range(len(parent_info_list) - 1, -1, -1):
                # Correct the resource type of the prior matched entry.
                if download_url == parent_info_list[j][0]:
                    parent_info_list[j][1] = 'Download'
                    break

    # Modify the parent source of the frame navigation-related 'requestWillBeSent' entries.
    tar_idx = 1
    for navigate_item in frame_navigate_info_list:
        is_matched = False
        while not is_matched and tar_idx < len(parent_info_list):
            # Only the 'Document' type entries need to be modified.
            # Match the properties: frame_id, navigate_url, and timestamp, where the timestamp difference should be small.
            if parent_info_list[tar_idx][1] == 'Document' and \
                    parent_info_list[tar_idx][5] == navigate_item[0] and \
                    parent_info_list[tar_idx][0] == navigate_item[1] and \
                    abs(parent_info_list[tar_idx][4] - navigate_item[3]) < 20:
                parent_info_list[tar_idx][3] = navigate_item[2]
                is_matched = True
            tar_idx += 1

    return parent_info_list


def build_redirection_tree(domain_sample: str, request_info_list: list) -> Optional[RedirectionTree]:
    """
    Given the request info, construct the connection between different requests, and build the redirection tree.
    :param domain_sample: domain name
    :param request_info_list: [[request_url, resource_type, parent_url, parent_source, timestamp], ...]
    :return:
    """
    tree = None
    node_list = list()

    for i, info_item in enumerate(request_info_list):
        if i == 0 and info_item[1] == 'Document' and not info_item[2] and info_item[3] == 'root':
            root_node = Node(url=info_item[0], parent_source=info_item[3],
                             resource_type=info_item[1], timestamp=info_item[4])
            tree = RedirectionTree(root=root_node)
            # Insert the root node.
            node_list += [root_node]
        else:
            # Get the matched parent node.
            # Because the parent node is always not so far from the current node.
            # Therefore, reverse lookup will speed up the matching of parent node.
            parent_node = None
            for prior_node in node_list[::-1]:
                if prior_node.url + prior_node.url_fragment == info_item[2]:
                    parent_node = prior_node
                    break
            # Ignore the isolated nodes.
            if not parent_node:
                continue

            url, fragment = info_item[0], ''
            if '#' in info_item[0]:
                url_parts = info_item[0].split('#')
                url, fragment = url_parts[0], '#' + '#'.join(url_parts[1:])
            node = Node(url=url, url_fragment=fragment, parent=parent_node, parent_source=info_item[3],
                        resource_type=info_item[1], timestamp=info_item[4])
            tree.add_node(node)

            # Insert the newly constructed node to the end of node list.
            node_list += [node]

    return tree


def get_iframe_info(domain_sample: str, sample_dir: str, intersect_ratio: float = 0.4) -> list:
    """
    Given the sample, get the iframe tag info based on the 'redirection_tags.txt' file.
    Get the intersection area of current iframe and its parent frame based on the rect of the current iframe.
    If the intersection area exceeds the specific ratio, the corresponding iframe is considered as one redirection.
    Do not consider the nested iframes here.
    :param domain_sample:
    :param sample_dir:
    :param intersect_ratio:
    :return:
    """
    def get_intersect_rect(rect1: dict, rect2: dict) -> dict:
        """
        Given two rects, get their intersecting rect part.
        A rect is composed of top-left coordinates (x, y), width, and height.
        :param rect1:
        :param rect2:
        :return:
        """
        tl_x = max(rect1['x'], rect2['x'])
        tl_y = max(rect1['x'], rect2['y'])
        br_x = min(rect1['x'] + rect1['width'], rect2['x'] + rect2['width'])
        br_y = min(rect1['y'] + rect1['height'], rect2['y'] + rect2['height'])
        intersect_rect = {'x': tl_x, 'y': tl_y, 'width': br_x - tl_x, 'height': br_y - tl_y}
        return intersect_rect

    main_rect = {'x': 0, 'y': 0, 'width': 1664, 'height': 919}
    main_area = main_rect['width'] * main_rect['height']

    # Extract the size and src of visible iframes.
    iframe_info_list = list()
    file_path = os.path.join(sample_dir, 'redirection_tags.txt')
    with open(file_path, 'r', encoding='utf-8') as fr:
        for line in fr:
            line = line.strip('\n').split('\t')
            tag_type = line[1]
            if tag_type != 'iframe':
                continue

            is_visible = int(line[2]), eval(line[3])
            tag_rect_list = eval(line[3])       # One tag (e.g., <img>) may contain multiple clickable rect.
            # Filter the invisible iframes.
            if is_visible == 0 or not tag_rect_list:
                continue
            iframe_rect = tag_rect_list[0]

            # Get the intersection rect.
            intersect_rect = get_intersect_rect(main_rect, iframe_rect)
            intersect_area = intersect_rect['width'] * intersect_rect['height']
            if intersect_area >= intersect_ratio * main_area:
                tag_html = etree.HTML(''.join(line[4]))     # Convert to HTML format.
                # Consider two tag types: iframe, frame. Ignore 'object' here.
                iframe_tag_list = tag_html.xpath('//iframe[@src]')
                frame_tag_list = tag_html.xpath('//frame[@src]')
                iframe_tag_list += frame_tag_list
                # Filter the tags without 'src' attribute here.
                if not iframe_tag_list:
                    continue

                iframe_attribute_dict = iframe_tag_list[0].attrib
                iframe_src = ''
                # iframe, frame.
                if 'src' in iframe_attribute_dict:
                    iframe_src = iframe_attribute_dict['src']
                # object
                elif 'data' in iframe_attribute_dict:
                    iframe_src = iframe_attribute_dict['data']

                # Ignore the redundant spacings in the head and tail of the 'src', and filter the invalid 'src'.
                iframe_src = iframe_src.strip(' ')
                if not iframe_src:
                    continue

                iframe_info = (iframe_rect, iframe_src)
                iframe_info_list += [iframe_info]

    return iframe_info_list


def modify_redirection_info(domain_sample: str, end_url: str, sample_dir: str) -> Optional[list]:
    """
    Modify the redirection info, including the URL and parent source of corresponding redirection node, of prior crawling samples.
        1. Form the redirection tree;
        2. Check whether there are large iframes covering the webpage;
        3. Check whether there are drive-by download events;
        4. Aggregate the node between start URL and end URL to get the redirection chain;
        5. Aggregate the request methods employed by the redirection-related nodes (namely the redirection methods).
    :param domain_sample: domain string
    :param end_url:
    :param sample_dir:
    :return: [redirection nodes, redirection methods, hops, iframe or not, download or not, download URL]
    """
    # 1. Form the redirection tree.
    entry_list = extract_target_entries(domain_sample, sample_dir, None)
    parent_info_list = get_parent_info(entry_list)
    r_tree = build_redirection_tree(domain_sample, parent_info_list)
    if not r_tree:
        return None
    end_url_node = r_tree.search_node(end_url)
    if not end_url_node:
        return None
    redirection_intermediaries = r_tree.get_intermediaries(end=end_url_node)
    if not redirection_intermediaries:
        return None

    hops = len(redirection_intermediaries) - 1
    inter_url_list = list()
    inter_method_list = list()
    inter_resource_type_list = list()
    for node in redirection_intermediaries:
        inter_url_list += [node.url + node.url_fragment]
        inter_method_list += [node.parent_source]
        inter_resource_type_list += [node.resource_type]

    # 2. Check whether there are large iframes covering the webpage.
    large_iframe_list = get_iframe_info(domain_sample, sample_dir)
    has_large_iframe = False
    if large_iframe_list:
        iframe_src = large_iframe_list[0][1]        # Only consider the first iframe.
        has_large_iframe = True
        hops += 1

        # Proactively label the URL query parameter and fragment (notice the only '?' and only '#' symbol cases).
        temp_src = iframe_src
        src_has_fragment = False
        if '#' in temp_src:
            src_has_fragment = True
            temp_src, _ = temp_src.split('#', 1)
        src_has_query = False
        if '?' in temp_src:
            src_has_query = True
            temp_src, _ = temp_src.split('?', 1)
        src_has_params = False
        if ';' in temp_src:
            src_has_params = True
            temp_src, _ = temp_src.split(';', 1)

        # Complement and modify the URL path. SplitResult(scheme, netloc, path, query, fragment).
        # Some iframe tags have only relative paths in the 'src' attribute.
        src_parts = parse.urlsplit(iframe_src)       # urlsplit() function has no 'params' field.
        if not src_parts.scheme or not src_parts.netloc:
            iframe_src = parse.urljoin(inter_url_list[-1], iframe_src)

        # Split the URL into six parts.
        src_parts = parse.urlparse(iframe_src)
        scheme = src_parts.scheme
        netloc = src_parts.netloc
        path = src_parts.path
        params = src_parts.params
        query = src_parts.query
        fragment = src_parts.fragment

        iframe_src = scheme + '://' + netloc
        if path:
            iframe_src += path
        else:
            iframe_src += '/'
        if src_has_params:
            iframe_src += ';' + params
        if src_has_query:
            iframe_src += '?' + query
        if src_has_fragment:
            iframe_src += '#' + fragment

        iframe_src = get_valid_url(iframe_src)
        iframe_node = r_tree.search_node(iframe_src)
        if not iframe_node:
            print('%s - Cannot find the iframe-src in the formed tree: %s' % (domain_sample, iframe_src))
            return None
        inter_url_list += [iframe_node.url + iframe_node.url_fragment]
        inter_method_list += [iframe_node.parent_source]
    if has_large_iframe:
        has_large_iframe = 'has_iframe'
    else:
        has_large_iframe = 'no_iframe'

    # 3. Check whether there are drive-by download events.
    has_download = False
    download_url = ''
    for parent_info in parent_info_list:
        if parent_info[1] == 'Download':
            has_download = True
            download_url = parent_info[0]
    if has_download:
        has_download = 'has_download'
    else:
        has_download = 'no_download'

    redirection_info = [' '.join(inter_url_list), ';'.join(inter_method_list), str(hops),
                        has_large_iframe, has_download, download_url]
    return redirection_info


def get_cur_samples() -> None:
    """
    For the construction of the recently crawled samples.
    Run this function everyday to aggregate the newly crawling samples.
    :return:
    """
    sample_root_dir = r'E:\redirection_samples\xinda'
    cur_crawling_file = r'./data/cur_samples.txt'
    cur_chain_info_list = list()
    with open(cur_crawling_file, 'r', encoding='utf-8') as fr:
        for i, line in enumerate(fr):
            line = line.strip('\n').split('\t')
            domain = line[0]
            sample = line[1]
            start_url, end_url = line[5], line[6]
            sample_dir = os.path.join(sample_root_dir, sample)
            chain_info = modify_redirection_info(domain, end_url, sample_dir)
            # Ignore the samples that do not involve redirections.
            if chain_info[2] == '0':
                continue
            chain_info = [domain, 'malicious', sample, end_url] + chain_info
            print(i, chain_info)
            chain_info_str = '\t'.join(chain_info) + '\n'
            cur_chain_info_list += [chain_info_str]

    # # Save the reconstructed redirection samples.
    # cur_sample_file = r'./data/cur_entries.txt'
    # with open(cur_sample_file, 'w', encoding='utf-8') as fw:
    #     for info in cur_chain_info_list:
    #         fw.write(info)


def get_modified_samples() -> None:
    """
    For the reconstruction of redirection samples.
    Here, we ignore the samples without redirection. That is, only reserve the samples with hops greater than 1.
    :return:
    """
    sample_root_dir_dict = {
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

    m_origin_sample_file = r'data/origin_malicious_entries.txt'
    m_chain_info_list = list()
    with open(m_origin_sample_file, 'r', encoding='utf-8') as fr:
        for i, line in enumerate(fr):
            line = line.strip('\n').split('\t')
            domain, label, source, end_url = line[0], line[1], line[2], line[3]
            cur_sample_dir = os.path.join(sample_root_dir_dict[source], domain)
            chain_info = modify_redirection_info(domain, end_url, cur_sample_dir)
            # Ignore the samples that do not involve redirections.
            if chain_info[2] == '0':
                continue
            chain_info = [domain, label, source, end_url] + chain_info
            print(i, chain_info)
            chain_info_str = '\t'.join(chain_info) + '\n'
            m_chain_info_list += [chain_info_str]
    # Save the reconstructed redirection samples.
    m_modify_sample_file = r'data/modified_malicious_entries.txt'
    with open(m_modify_sample_file, 'w', encoding='utf-8') as fw:
        for info in m_chain_info_list:
            fw.write(info)

    b_origin_sample_file = r'data/origin_benign_entries.txt'
    b_chain_info_list = list()
    with open(b_origin_sample_file, 'r', encoding='utf-8') as fr:
        for i, line in enumerate(fr):
            line = line.strip('\n').split('\t')
            domain, label, source, end_url = line[0], line[1], line[2], line[3]
            cur_sample_dir = os.path.join(sample_root_dir_dict[source], domain)
            chain_info = modify_redirection_info(domain, end_url, cur_sample_dir)
            # Ignore the samples that do not involve redirections.
            if chain_info[2] == '0':
                continue
            chain_info = [domain, label, source, end_url] + chain_info
            print(i, chain_info)
            chain_info_str = '\t'.join(chain_info) + '\n'
            b_chain_info_list += [chain_info_str]
    # Save the reconstructed redirection samples.
    b_modify_sample_file = r'data/modified_benign_entries.txt'
    with open(b_modify_sample_file, 'w', encoding='utf-8') as fw:
        for info in b_chain_info_list:
            fw.write(info)


def get_tar_response(domain_sample: str, sample_dir: str, tar_id_list: Optional[list] = None) -> dict:
    """
    Extract the matched response entry of each request entry of the given sample.
    If the tar_id_list parameter is specified, return the corresponding response info of the target request IDs.
    :param domain_sample:
    :param sample_dir:
    :param tar_id_list: The default value of this parameter is None, a request ID list otherwise.
    :return:
    """
    response_entry_dict = dict()
    response_file = os.path.join(sample_dir, 'response_log.txt')
    with open(response_file, 'r', encoding='utf-8') as fr:
        for i, line in enumerate(fr):
            line = line.strip('\n')
            line_entry_dict = eval(line)
            request_id = line_entry_dict['requestId']
            body = line_entry_dict['body']
            if tar_id_list:
                if request_id in tar_id_list:
                    response_entry_dict[request_id] = body
            else:
                response_entry_dict[request_id] = body
    return response_entry_dict


def node_reverse_lookup(node: Node, entry_list: list) -> Optional[dict]:
    """
    Given the tree node and the entries, get the matching request entry.
    :param node:
    :param entry_list: [dict1, dict2, ...]
    :return: entry or None
    """
    node_url = node.url + node.url_fragment

    for entry in entry_list:
        if entry['method'] != 'Network.requestWillBeSent':
            continue
        if entry['params']['type'] != node.resource_type:
            continue
        if entry['timestamp'] != node.timestamp:
            continue

        # Compare URL.
        entry_url = entry['params']['request']['url']
        if 'urlFragment' in entry['params']['request']:
            entry_url += entry['params']['request']['urlFragment']
        if entry_url != node_url:
            continue
        return entry

    return None


def extract_initiators_from_tree(r_tree: RedirectionTree, r_node_list: list, entry_list: list) -> dict:
    """
    Extract the initiator nodes from the given redirection tree.
    :param r_tree:
    :param r_node_list:
    :param entry_list:
    :return:
    """
    # By default, we only consider the script-related initiating methods.
    tar_methods = {'anchorClick', 'script', 'scriptInitiated'}

    initiator_node_dict = dict()  # Key is the redirection node, value is the related initiator node.
    # Ignore the root node.
    for i, node in enumerate(r_node_list[1:], 1):
        if node.parent_source not in tar_methods:
            continue

        # Review the performance entries to get its initiating-related info.
        tar_entry = node_reverse_lookup(node, entry_list)
        cur_initiator_dict = tar_entry['params']['initiator']

        initiator_url = ''
        if 'url' in cur_initiator_dict:
            initiator_url = cur_initiator_dict['url']
        elif 'stack' in cur_initiator_dict:
            # The first entry in the call frame stack is the last initiator (actual) issues this request.
            for call_frame in cur_initiator_dict['stack']['callFrames']:
                if call_frame['url'] != '':
                    initiator_url = call_frame['url']
                    break
            if initiator_url == '':
                initiator_url = node.parent.url  # Ignore the URL fragment in searching initiator URL.

        initiator_node = r_tree.get_initiator_node(initiator_url, node)  # Ignore the URL fragment.
        if not initiator_node:
            print('No matching node of such URL in this tree: %s.' % initiator_url)
            continue
        initiator_node_dict[node] = initiator_node

    return initiator_node_dict


def get_redirect_initiators(domain: str, sample_dir: str, end_url: str) -> dict:
    """
    This function focuses on extracting the initiator node of each redirection.
    Actually, the initiator here not refers to the parent node, but the specific node that issues the redirect command.
    The initiator node here not just Document node, mostly Script node.

    Specifically, the following steps are required to get the actual initiator of certain redirections:
        1). Build the redirection tree, and get the related redirection chain;
        2). Review the performance log to get the actual initiator (mostly script node) of each redirection.

    Note that, in performance log, the URL fragment of initiator is ignored.
    Because the fragment just indicates the switching to target anchor, which will not change the URL and HTML content.
    That is to say, we can ignore the fragment in searching the initiator URL.
    :param domain:
    :param sample_dir:
    :param end_url: Used to label the last node of the redirection chain.
    :return:
    """
    entry_list = extract_target_entries(domain, sample_dir)
    parent_info_list = get_parent_info(entry_list)
    r_tree = build_redirection_tree(domain, parent_info_list)
    r_node_list = r_tree.get_intermediaries(None, end_url)
    initiator_node_dict = extract_initiators_from_tree(r_tree, r_node_list, entry_list)
    return initiator_node_dict


def aggregate_script_initiating_samples() -> None:
    """
    Based on the built redirection tree, extract the actual initiator info of each redirection.
    Here, we focus on script-related redirections.
    The format of initiator info are as follows, involving the basic info of hop node and the related initiator node:
        [domain, label, source,
         hop_node_url, hop_node_method, hop_node_timestamp,
         initiator_url, initiator_resource_type, initiator_timestamp]
    :return:
    """
    # Prior samples.
    sample_root_dir_dict = {
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
        'zeng_temp': r'E:\redirection_samples\zengyuwei\tag_info_temp'
    }
    sample_list = list()
    # # Prior malicious samples.
    # m_file = './data/modified_malicious_entries.txt'
    # with open(m_file, 'r', encoding='utf-8') as fr:
    #     for line in fr:
    #         line = line.strip('\n').split('\t')
    #         domain, label, source, end_url, chain = line[:5]
    #         has_iframe = line[7]
    #         if has_iframe == 'has_iframe':
    #             end_url = chain.split(' ')[-1]
    #         sample_dir = os.path.join(sample_root_dir_dict[source], domain)
    #         sample = [domain, label, source, end_url, sample_dir]
    #         sample_list += [sample]
    # Prior benign samples.
    b_file = './data/modified_benign_entries.txt'
    with open(b_file, 'r', encoding='utf-8') as fr:
        for line in fr:
            line = line.strip('\n').split('\t')
            domain, label, source, end_url, chain = line[:5]
            has_iframe = line[7]
            if has_iframe == 'has_iframe':
                end_url = chain.split(' ')[-1]
            sample_dir = os.path.join(sample_root_dir_dict[source], domain)
            sample = [domain, label, source, end_url, sample_dir]
            sample_list += [sample]

    # # Current samples.
    # sample_list = list()
    # c_file = './data/cur_entries.txt'
    # with open(c_file, 'r', encoding='utf-8') as fr:
    #     for line in fr:
    #         line = line.strip('\n').split('\t')
    #         domain, label, source = line[0], line[1], line[2]
    #         end_url = line[3]
    #         sample_dir = r'E:\redirection_samples\xinda'
    #         sample_dir = os.path.join(sample_dir, source)
    #         sample_list += [[domain, label, source, end_url, sample_dir]]

    # Search initiator nodes.
    initiator_info_list = list()
    for i, sample in enumerate(sample_list):
        domain, label, source, end_url, sample_dir = sample
        print(i, domain, source)
        initiator_node_dict = get_redirect_initiators(domain, sample_dir, end_url)
        if not initiator_node_dict:
            continue
        # Aggregate the initiator info.
        for key_node in initiator_node_dict:
            hop_url = key_node.url + key_node.url_fragment
            hop_resource_type = key_node.resource_type
            hop_timestamp = str(key_node.timestamp)
            initiator_url = initiator_node_dict[key_node].url
            initiator_resource_type = initiator_node_dict[key_node].resource_type
            initiator_timestamp = str(initiator_node_dict[key_node].timestamp)
            cur_initiator_info = [domain, label, source,
                                  hop_url, hop_resource_type, hop_timestamp,
                                  initiator_url, initiator_resource_type, initiator_timestamp]
            initiator_info_list += [cur_initiator_info]
            print('\t%s (%s, %s) --> %s (%s, %s)' %
                  (initiator_url, initiator_resource_type, initiator_timestamp,
                   hop_url, hop_resource_type, hop_timestamp))

    # Save the initiator basic info.
    # initiator_file = r'./data/malicious_initiator_entries.txt'
    initiator_file = r'./data/benign_initiator_entries.txt'
    # initiator_file = r'./data/cur_initiator_entries.txt'
    with open(initiator_file, 'w', encoding='utf-8') as fw:
        for entry in initiator_info_list:
            entry = '\t'.join(entry) + '\n'
            fw.write(entry)


def get_initiator_node_info() -> dict:
    """
    Measure the common initiator of different redirection chains.
    Here, we should make sure that the employed initiators are originated from different samples.

    The format of the initiator_info_dict is as follows:
        initiator_info_dict = {
            'initiator_url_1': {
                'samples' : {
                    'sample1': [redirect_url_1, ...]
                }
                'e2lds': involved e2LD of the redirect URL
                'freq': involved redirects
                'type': 'Script' or some others
            }
        }
    :return:
    """
    psl = PublicSuffixList(accept_unknown=False, only_icann=True)
    m_initiator_file = r'./data/malicious_initiator_entries.txt'
    # Key is initiator URL, value is a sample dict. More details can refer to the notation of this func.
    initiator_dict = dict()
    with open(m_initiator_file, 'r', encoding='utf-8') as fr:
        for line in fr:
            line = line.strip('\n').split('\t')
            sample = line[0] + ':' + line[2]
            redirect_url = line[3]
            initiator_url = line[6]
            initiator_type = line[7]
            if initiator_url in initiator_dict:
                if sample not in initiator_dict[initiator_url]['samples']:
                    initiator_dict[initiator_url]['samples'][sample] = [redirect_url]
                else:
                    initiator_dict[initiator_url]['samples'][sample] += [redirect_url]
                initiator_dict[initiator_url]['freq'] += 1
                e2ld = psl.privatesuffix(parse.urlsplit(redirect_url).netloc)
                if e2ld not in initiator_dict[initiator_url]['e2lds']:
                    initiator_dict[initiator_url]['e2lds'] += [e2ld]
            else:
                initiator_dict[initiator_url] = {'samples': dict(), 'e2lds': list(),
                                                 'freq': 1, 'type': initiator_type}
                initiator_dict[initiator_url]['samples'][sample] = [redirect_url]
                e2ld = psl.privatesuffix(parse.urlsplit(redirect_url).netloc)
                initiator_dict[initiator_url]['e2lds'] = [e2ld]

    return initiator_dict


def request_static_resource(resource_url: str) -> Optional[dict]:
    """
    Get the HTTP response content of the given Web resource URL.
    Due to Selenium crawling cannot get the specific HTTP response content of resources of prior frames in redirections.
    We should request the target resource (mostly HTML and JavaScript file) again to complement the experiment data.
    :param resource_url:
    :return:
    """
    content_dict = None
    headers = {'Connection': 'close'}  # Avoid persistent connection.
    try:
        print('Requesting %s ...' % resource_url)
        response = requests.get(resource_url, headers=headers, verify=False)
        print('\t%s' % response.headers)
        content_dict = {'content_type': response.headers['Content-Type'], 'content': response.text}
        response.close()
    except:
        print("Exception occurred in requesting %s ..." % resource_url)

    return content_dict


def gather_initiator_content(url_list: list) -> None:
    """
    Run this func every day to capture redirection fluxing cases.
    The naming format of the initiator content is 'domain_datetime_filename.filetype'.
    :param url_list:
    :return:
    """
    initiator_dict = dict()
    for url in url_list:
        content_dict = request_static_resource(url)
        if not content_dict:
            continue
        time.sleep(10)
        initiator_dict[url] = content_dict
    root_dir = './initiator_content'
    for url in initiator_dict:
        url_parts = parse.urlsplit(url)
        domain = url_parts.netloc
        
        if ':' in domain:        # Ignore the port.
            domain = domain.split(':')[0]
        initiator_file_name = url_parts.path.split('/')[-1]
        if initiator_file_name == '':
            initiator_file_name = '.html'
        # Append the timestamp to differentiate the multiple crawling of the same initiator content.
        dt = datetime.now()
        dt_str = '-'.join(['{:0>4s}'.format(str(dt.year)), '{:0>2s}'.format(str(dt.month)), '{:0>2s}'.format(str(dt.day)),
                           '{:0>2s}'.format(str(dt.hour)), '{:0>2s}'.format(str(dt.minute)), '{:0>2s}'.format(str(dt.second))])
        saved_file_name = '%s_%s_%s' % (domain, dt_str, initiator_file_name)

        saved_file_name = os.path.join(root_dir, saved_file_name)
        with open(saved_file_name, 'w', encoding='utf-8') as fw:
            content = initiator_dict[url]['content']
            fw.write(content)


def dump_samples():
    """
    Store the detailed Node info of the crawling samples.
    The stored info should be consistent with the attributes of Node object, including:
        1). Node identifier;
        2). URL (including fragment);
        3). Parent identifier;
        4). Parent source;
        5). Resource type;
        6). Timestamp;
        7). Children identifier list.
    Here, the node identifier is represented as 'node_i' to identify the i-th node.

    Each node is stored as an entry in the following format:
        [domain, label, source, node_id, url, parent_id, parent_source, resource_type, timestamp, child_id_list]

    The procedures are as follows:
        1. Build the redirection tree;
        2. Traverse the tree with BFS and extract the corresponding node info;
        3. Save the node info.
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

    prior_m_entry_file = r'./data/modified_malicious_entries.txt'   # prior malicious sample entries
    prior_b_entry_file = r'./data/modified_benign_entries.txt'      # prior benign sample entries
    cur_entry_file = r'./data/cur_entries.txt'  # cur malicious sample entries

    prior_m_sample_list = list()
    with open(prior_m_entry_file, 'r', encoding='utf-8') as fr:
        for line in fr:
            line = line.strip('\n').split('\t')
            domain, label, source = line[0], line[1], line[2]
            end_url = line[3]
            prior_m_sample_list += [[domain, label, source, end_url]]
    prior_b_sample_list = list()
    with open(prior_b_entry_file, 'r', encoding='utf-8') as fr:
        for line in fr:
            line = line.strip('\n').split('\t')
            domain, label, source = line[0], line[1], line[2]
            end_url = line[3]
            prior_b_sample_list += [[domain, label, source, end_url]]
    cur_sample_list = list()
    with open(cur_entry_file, 'r', encoding='utf-8') as fr:
        for line in fr:
            line = line.strip('\n').split('\t')
            domain, label, source = line[0], line[1], line[2]
            end_url = line[3]
            cur_sample_list += [[domain, label, source, end_url]]

    # Process sample entries.
    prior_m_tree_info_list = list()
    prior_b_tree_info_list = list()
    cur_tree_info_list = list()
    for i, prior_sample_list in enumerate([prior_m_sample_list, prior_b_sample_list, cur_sample_list]):
        for item in prior_sample_list:
            domain, label, source, end_url = item
            if source in sample_source_dict:        # Prior samples.
                sample_dir = os.path.join(sample_source_dict[source], domain)
            else:       # Current samples.
                sample_dir = os.path.join(sample_source_dict['xinda'], source)
            entry_list = extract_target_entries(domain, sample_dir)
            parent_info_list = get_parent_info(entry_list)
            r_tree = build_redirection_tree(domain, parent_info_list)
            if not r_tree:
                continue
            node_list = r_tree.bfs_traverse()
            print('%s:%s \t Tree node cnt: %s' % (domain, source, len(node_list)))

            # Node identifier.
            node_id_dict = dict()
            for j, node in enumerate(node_list):
                node_id_dict[node] = 'node_' + str(j)

            # Extract node info.
            for node in node_list:
                node_id = node_id_dict[node]
                url = node.url + node.url_fragment
                parent_id = ''
                if node.parent:
                    parent_id = node_id_dict[node.parent]
                parent_source = node.parent_source
                resource_type = node.resource_type
                timestamp = str(node.timestamp)
                children_id_list = list()
                for child in node.children_list:
                    child_id = node_id_dict[child]
                    children_id_list += [child_id]
                cur_node_info = [domain, label, source, node_id, url, parent_id, parent_source, resource_type, timestamp, children_id_list]
                # Different sample type: prior malicious, prior benign, and current malicious.
                if i == 0:
                    prior_m_tree_info_list += [cur_node_info]
                elif i == 1:
                    prior_b_tree_info_list += [cur_node_info]
                else:
                    cur_tree_info_list += [cur_node_info]

    # Save the tree info.
    prior_m_tree_file = r'./data/malicious_tree_node_info.txt'
    prior_b_tree_file = r'./data/benign_tree_node_info.txt'
    cur_tree_file = r'./data/cur_tree_node_info.txt'
    # Prior malicious tree.
    with open(prior_m_tree_file, 'w', encoding='utf-8') as fw:
        for item in prior_m_tree_info_list:
            children_id_str = ' '.join(item[-1])
            temp_list = item[:-1]
            item_str = '\t'.join(item[:-1] + [children_id_str]) + '\n'
            fw.write(item_str)
    # Prior benign tree.
    with open(prior_b_tree_file, 'w', encoding='utf-8') as fw:
        for item in prior_b_tree_info_list:
            children_id_str = ' '.join(item[-1])
            item_str = '\t'.join(item[:-1] + [children_id_str]) + '\n'
            fw.write(item_str)
    # Current malicious tree.
    with open(cur_tree_file, 'w', encoding='utf-8') as fw:
        for item in cur_tree_info_list:
            children_id_str = ' '.join(item[-1])
            item_str = '\t'.join(item[:-1] + [children_id_str]) + '\n'
            fw.write(item_str)


def recover_tree(tar_sample: Optional[str] = None, label: Optional[str] = None) -> Optional[dict]:
    """
    Extract the request info from the 'tree_node_info' file.
    The format of the node info entry is as follows:
        [domain, label, source, node_id, url, parent_id, parent_source, resource_type, timestamp, children_id_list]
    If the 'sample' param is not specified, parse and extract all the entries.

    Note that, the node info is saved in layer-traversing format.
    Therefore, the node info can be parsed directly without considering the sequence issue.
    :param tar_sample: 'domain:source'
    :param label: 'malicious' or 'benign'
    :return: {sample: tree_obj, ...}
    """
    m_node_info_file = r'./data/malicious_tree_node_info.txt'
    b_node_info_file = r'./data/benign_tree_node_info.txt'
    c_node_info_file = r'./data/cur_tree_node_info.txt'
    file_list = [b_node_info_file, m_node_info_file, c_node_info_file]
    if label == 'malicious':
        file_list = file_list[1:]
    elif label == 'benign':
        file_list = [file_list[0]]
    elif label:
        return None

    tar_sample_dict = dict()
    found = False       # Indicate whether all the target sample's node info have been found.
    for node_file in file_list:
        if found:
            break
        with open(node_file, 'r', encoding='utf-8') as fr:
            for line in fr:
                line = line.strip('\n').split('\t')
                domain, label, source = line[0], line[1], line[2]
                cur_sample = domain + ':' + source
                node_id, url = line[3], line[4]
                parent_id, parent_source = line[5], line[6]
                res_type, timestamp = line[7], line[8]
                children_id_list = line[9].split(' ')
                cur_node_info = [node_id, url, parent_id, parent_source, res_type, timestamp, children_id_list]

                if tar_sample:
                    # Check whether the target sample have all been loaded.
                    if tar_sample in tar_sample_dict and tar_sample != cur_sample:
                        found = True
                        break
                    elif tar_sample == cur_sample:
                        if cur_sample in tar_sample_dict:
                            tar_sample_dict[cur_sample] += [cur_node_info]
                        else:
                            tar_sample_dict[cur_sample] = [cur_node_info]
                else:
                    if cur_sample in tar_sample_dict:
                        tar_sample_dict[cur_sample] += [cur_node_info]
                    else:
                        tar_sample_dict[cur_sample] = [cur_node_info]

    # Recover the tree.
    sample_tree_dict = dict()
    for sample in tar_sample_dict:
        cur_tree = None
        node_dict = dict()      # Reserve the
        for i, node_info in enumerate(tar_sample_dict[sample]):
            node_id, url = node_info[0], node_info[1]
            parent_id, parent_source = node_info[2], node_info[3]
            res_type, timestamp = node_info[4], int(node_info[5])
            if i == 0 and node_id == 'node_0':
                root_node = Node(url=url, parent_source=parent_source,
                                 resource_type=res_type, timestamp=timestamp)
                cur_tree = RedirectionTree(root=root_node)
                node_dict[node_id] = root_node
            else:
                if parent_id not in node_dict:
                    print('Sample %s has not such node: %s' % (sample, parent_id))
                    cur_tree = None
                    break
                parent_node = node_dict[parent_id]

                fragment = ''
                if '#' in url:
                    url_parts = url.split('#', 1)
                    url, fragment = url_parts[0], '#' + url_parts[1]
                node = Node(url=url, url_fragment=fragment, parent=parent_node, parent_source=parent_source,
                            resource_type=res_type, timestamp=timestamp)
                cur_tree.add_node(node)

                # Add the newly constructed node to the node dict.
                node_dict[node_id] = node
        sample_tree_dict[sample] = cur_tree

    return sample_tree_dict


if __name__ == "__main__":
    gather_initiator_content(['http://01bxbx.com'])     # www.01qxqx.com; 02qxqx.com; 01bxbx.com; jjc37.com
    # recover_tree()

    # sample_list = list()
    # sample_file = './data/cur_samples.txt'
    # with open(sample_file, 'r', encoding='utf-8') as fr:
    #     for line in fr:
    #         line = line.strip('\n').split('\t')
    #
    #         domain, sample_tag = line[0], line[1]
    #         end_url = line[6]
    #         sample_dir = os.path.join(os.path.abspath('samples'), sample_tag)
    #         sample_list += [[domain, sample_dir, end_url]]
    # for item in sample_list:
    #     get_redirect_initiators(item[0], item[1], item[2])

    # aggregate_script_initiating_samples()
