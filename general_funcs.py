# -*-coding: utf-8 -*-

"""
@author: zyw
@file  : general_funcs.py
@date  : 2024/1/17
"""

import os
from urllib.parse import urlparse, urlsplit, urljoin, quote, unquote
from publicsuffixlist import PublicSuffixList
from typing import Optional


def get_valid_url(original_url: str) -> Optional[str]:
    """
    1. Given a URL, check whether it has redundant hex-format characters;
       1). digits (0-9): [48, 57];
       2). Uppercase alphabets (A-Z): [65, 90];
       3). Lowercase alphabets (a-z): [97, 122];
       4). Necessary symbols (:/.-?&=#): (58, 47, 46, 45, 63, 38, 61, 35)
    2. Check and convert the HTML-escape characters;
    3. Convert the IDN domain to punycode-encoded domain;
    4. Filter the invalid URLs.

    The fields of 'urlparse' function are: scheme, netloc, path, params, query, fragment.
    According to observations, however, browsers do not differentiate between path, params, query.
    In specific, browsers will process them uniformly as URL path part.

    Some notations:
        - The scheme part does not support hex-decoding, including ':' and '//';
        - The netloc part support hex-decoding, including labels and split dots;
            - The valid characters of domain name are: alphabets, digits, and hyphen.
            - Other ascii characters in the domain name should be hex-encoded, e.g., '*';
            - Unicode characters in the domain name should be IDN-encoded (punycode).
        - The path part does not support hex-decoding, but the non-ascii characters will be hex-encoded.
    That is, only the netloc and non-ascii characters of the path part need to be checked.

    :param original_url:
    :return:
    """
    # Aggregate valid URL characters.
    valid_alpha_ascii_set = set(range(65, 91)).union(set(range(97, 123)))       # a-z, A-z
    valid_digit_ascii_set = set(range(48, 58))      # 0-9
    valid_symbol_ascii_set = {58, 47, 46, 45, 63, 38, 61, 35}       # :/.-?&=#

    # Some URLs mistakenly type '/' as '\'. Correct them.
    original_url = original_url.replace('\\', '/')
    # Convert HTML-escape characters.
    original_url = original_url.replace('&amp;', '&')

    # Proactively label the URL query parameter and fragment (notice the only '?' and only '#' symbol cases).
    temp_url = original_url
    has_fragment = False
    if '#' in temp_url:
        has_fragment = True
        temp_url, _ = temp_url.split('#', 1)
    has_query = False
    if '?' in temp_url:
        has_query = True
        temp_url, _ = temp_url.split('?', 1)
    has_params = False
    if ';' in temp_url:
        has_params = True
        temp_url, _ = temp_url.split(';', 1)

    # Split the URL into six parts, scheme, netloc, path, params, query, and fragment.
    url_parts = urlparse(original_url)
    scheme = url_parts.scheme
    netloc = url_parts.netloc
    path = url_parts.path
    params = url_parts.params
    query = url_parts.query
    fragment = url_parts.fragment

    # Filter the invalid (unwanted) URL.
    if scheme not in {'http', 'https'} or netloc == '':
        return None

    # Filter the explicitly introduced default port number.
    default_ports = {'http': '80', 'https': '443'}
    if ':' in netloc:
        netloc_parts = netloc.split(':')
        if default_ports[scheme] == netloc_parts[1]:
            netloc = netloc_parts[0]

    # Convert the redundant hex-format characters.
    netloc = unquote(netloc)

    # Check IDN domain.
    domain_label_list = netloc.split('.')
    for i, label in enumerate(domain_label_list):
        is_ascii = True
        for c in label:
            if ord(c) > 122:
                is_ascii = False
                break
        if not is_ascii:
            domain_label_list[i] = 'xn--' + str(label.encode('punycode'), encoding='utf-8')
    netloc = '.'.join(domain_label_list)

    # Modify the 'path', 'params', and 'query' field.
    # Path
    final_url = scheme + '://' + netloc
    if path == '':
        final_url += '/'
    else:
        # Check the non-Ascii characters/
        path = quote(path, safe="!@$%&*()-_+=/[]:',.~")
        if '/./' in url_parts.path:
            final_url += ''.join(path.split('./'))
        elif '/../' in path:
            path_parts = path.split('..')
            final_url += path_parts[0]
            for sub_path in path_parts[1:]:
                sub_path = '..' + sub_path
                final_url = urljoin(final_url, sub_path)
        else:
            final_url += path
    # params
    if has_params:
        # Check the non-Ascii characters.
        params = quote(params, safe="!@$%&*()-_=+/[]:',.~")
        final_url += ';' + params
    # query
    if has_query:
        # Check the non-Ascii characters.
        query = quote(query, safe="!@$%^&*()-_=+/?[]{}\|;:,.~`")
        final_url += '?' + query
    # fragment
    if has_fragment:
        # Check the non-Ascii characters.
        fragment = quote(fragment, safe="!@$%^&*()-_=+/?[]{}\|;:,.~`")
        final_url += '#' + fragment

    return final_url


def url_cmp(url_1: str, url_2: str) -> bool:
    """
    Due to the employment of URL encoding, it is difficult to compare two URLs directly.
    It is necessary to decode the URLs at first.
    Notice to use the lowercase.
    :param url_1:
    :param url_2:
    :return:
    """
    return unquote(url_1).lower() == unquote(url_2).lower()


def save_tag_info(tag_info_list: list, tag_type: str, save_dir: str) -> None:
    """
    Save the extracted tag info into the given directory.
    The ID of each tag can be represented as 'tag_type' + 'seq_num'.
    For example, the ID of the first two <a> tags are 'a_0 and 'a_1', respectively.
    The saved tag info are list as below:
        1). ID;
        2). tag type;
        3). visibility
        4). clickable rect list;
        5). outerHTML code.
    :param tag_info_list:
    :param tag_type:
    :param save_dir:
    :return:
    """
    # Set tag_type as the prefix of the tag ID.
    id_prefix = tag_type + '_'

    save_str = ''
    for i, info in enumerate(tag_info_list):
        cur_id = id_prefix + str(i)
        visibility = str(int(info[1]))
        rects = str(info[2])
        outer_html = info[3]
        # Merge the info into the saving-used string.
        save_str += '\t'.join([cur_id, visibility, rects, outer_html]) + '\n'

    tag_file_path = os.path.join(save_dir, 'redirection_tags.txt')
    with open(tag_file_path, 'a', encoding='utf-8') as fw:
        fw.write(save_str)
