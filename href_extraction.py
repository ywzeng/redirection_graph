# -*-coding: utf-8 -*-

"""
@author: zyw
@file  : href_extraction.py
@date  : 2024/1/23

This script aims at extracting the visible HTML tags that attracting users into interacting with the webpage.
The interaction mostly focuses on clicking through certain areas, namely text and images.

In this script, we only consider <a>, <area>, <iframe>, and the tags owning the 'onclick' attribute.
Here, we use 'xpath' to search the corresponding HTML tags.

The 'xpath' of the required HTML tags are as follows:
    <a>: //body//a
    <map>: //body//map
    Tags having 'usemap' attribute: //body//img[usemap]
    <area>: //body//map[@name='%s']//area
            //body//map[@id='%s']//area
    <iframe>: //iframe
    <frame>: //frame
    Tags having 'onclick' attribute: //body//*[@onclick]

Some <a> tags have multiple sub-tags inside. For example,
    <a>
        <span>
        <span>
        <div>
    </a>
Therefore, we should consider all the sub-tags within <a> tags that tags having 'onclick' attribute.

Specifically, we need to collect the following information:
    1). ID number;
    2). tag type;
    3). visibility;
    4). clickable area;
    5). outerHTML.

Notably, we should consider the information loaded by iframes as well.
Specifically, we should dynamically create iframe directories based on the ID number and the corresponding nesting relationships.
The root sample directory contains HTML file, href-tag file, performance log, response log, screenshot, and iframe directories (if any).
The iframe directory contains HTML file, href-tag file, and the iframe directories (if any).
"""

import os
import shutil

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement
from selenium.common.exceptions import StaleElementReferenceException


def get_a_rect(a_tag: WebElement) -> (bool, list):
    """
    Get the clickable rect of the given <a> tag.
    If the <a> tags have sub-tags inside, extracting the clickable rect of all of them.
    Return the visibility and the clickable rects of the given <a> tag.
    :param a_tag:
    :return: (bool, [rect1, rect2, ...])
    """
    rect_list = list()
    # Ignore the rect of invisible <a> tag.
    if not a_tag.is_displayed():
        return False, rect_list

    # Get all tags within the <a> tags.
    inner_tag_list = a_tag.find_elements(By.XPATH, './/*')

    # Handle the <a> tag that has no sub-tags, namely the <a> tag has only text inside.
    if len(inner_tag_list) == 0:
        rect_list += [a_tag.rect]
        return True, rect_list

    # Handle the <a> tag that has sub-tags.
    for inner_tag in inner_tag_list:
        if not inner_tag.is_displayed():
            continue
        # Note that, the nested tags would share the same rect, e.g., <i><img src='...'><\i>
        # In this case, <i> and <img> share the same rect.
        # Therefore, filter the already stored rect to avoid logging repeating clickable areas.
        # The heuristic for doing so is different rects may cause different interactions,
        #   while the same rects will only lead to the same interaction.
        inner_rect = inner_tag.rect
        if inner_rect not in rect_list:
            rect_list += [inner_rect]

    return True, rect_list


def get_a_tags(driver: webdriver.Chrome) -> list:
    """
    Get all <a> tags, and extract the following information:
        1). visibility;
        2). clickable rect;
        3). outerHTML.
    :param driver:
    :return:
    """
    a_tag_info_list = list()

    # Extract all <a> tags within the <body> tag through the 'xpath' searching method.
    a_tag_list = driver.find_elements(By.XPATH, '//body//a')
    if len(a_tag_list) == 0:
        return a_tag_info_list
    print("\tThe number of <a> tags is %d." % len(a_tag_list))

    # Extract the information.
    for a_tag in a_tag_list:
        try:
            is_visible, rect_list = get_a_rect(a_tag)
            outer_html = a_tag.get_attribute('outerHTML')
            outer_html = outer_html.replace('\n', ' ')
            outer_html = outer_html.replace('\r', '')
            a_tag_info_list += [(a_tag, is_visible, rect_list, outer_html)]
        except StaleElementReferenceException:
            continue

    return a_tag_info_list


def get_area_tags(driver: webdriver.Chrome) -> list:
    """
    This function focus on extracting the <area> tag and its internal <map> tag.
    The <map> tag is used to define an image map which is an image with clickable areas.
    The required attribute 'name' of <map> tag is associated with the 'usemap' attribute of specific <img> tag,
        which creates a relationship between the corresponding <img> tag and <map> tag.
    The <map> tag contains a number of <area> tags which actually defines the clickable areas in the image map.
    Noted, the 'coords' attribute and 'shape' attribute of <area> tag are used together to specify the size, shape, and placement of a clickable area.
        - If 'shape' is 'rect', then 'coords' is 'x1, y1, x2, y2', where '*1' and '*2' specify the top-left and bottom-right corner of the rectangle;
        - If 'shape' is 'circle', then 'coords' is 'x, y, r', where 'x, y' specifies the coordinate of circle center, and 'r' specify the radius;
        - If 'shape' is 'poly', then 'coords' is 'x1, y1, x2, y2, ..., xn, yn', where each 'x, y' pair specifies the vertex of the polygon.
    Another note, the value of 'coords' attribute of a <area> tag is actually the relative coordinates with respect to the top-left corner of the image.
    The coordinates of the top-left corner of an image are (0, 0).
    Here, we only consider 'circle' and 'rect' shapes, and extract the following information:
        1). visibility;
        2). clickable rect (absolute coordinates);
        3). outerHTML.
    :param driver:
    :return: [(area_tag_obj, visibility, click_rect, outerHTML), ...]
    """
    area_tag_info_list = list()

    # Extract all <map> tags within the <body> tag.
    map_tag_list = driver.find_elements(By.XPATH, '//body//map')

    # No <map> tags, no <area> tags.
    if len(map_tag_list) == 0:
        return area_tag_info_list

    # Get all the <img> tags with 'usemap' attribute.
    usemap_img_tag_list = driver.find_elements(By.XPATH, '//body//img[@usemap]')
    usemap_img_tag_dict = dict()
    for img_tag in usemap_img_tag_list:
        if img_tag.is_displayed():
            # The 'usemap' attribute value is started with a '#' symbol which should be ignored.
            usemap = img_tag.get_attribute('usemap')[1:]
            # Reserve the 'rect' property of <img> tags to infer the absolute coordinates of certain <area> tags.
            usemap_img_tag_dict[usemap] = [img_tag, img_tag.rect]

    # Handle the <map> tags.
    for map_tag in map_tag_list:
        # The 'name' and 'id' attributes matche the 'usemap' attribute of the corresponding <img> tag.
        map_name = map_tag.get_attribute('name')
        map_id = map_tag.get_attribute('id')

        area_tag_list = list()
        img_rect = dict()
        # Extract all <area> tags within the current <map> tag.
        # Only consider the <map> tag corresponds to visible <img> tag.
        if map_name in usemap_img_tag_dict:
            img_rect = usemap_img_tag_dict[map_name][1]
            area_tag_list = map_tag.find_elements(By.XPATH, "//body//map[@name='%s']//area" % map_name)
        elif map_id in usemap_img_tag_dict:
            img_rect = usemap_img_tag_dict[map_id][1]
            area_tag_list = map_tag.find_elements(By.XPATH, "body//map[@name='%s']//area" % map_id)
        print("\tThe number of <area> tags is %d." % len(area_tag_list))

        # Get the absolute coordinates based on the shape and relative coordinates of each <area> tag.
        for area_tag in area_tag_list:
            area_shape = area_tag.get_property('shape')
            area_coord = area_tag.get_property('coords')
            rect_x, rect_y, width, height = 0, 0, 0, 0
            if area_shape == 'rect':
                area_coord = [int(i) for i in area_coord.split(',')]
                rect_x = img_rect['x'] + area_coord[0]
                rect_y = img_rect['y'] + area_coord[1]
                width = area_coord[2] - area_coord[0]
                height = area_coord[3] - area_coord[1]
            elif area_shape == 'circle':
                area_coord = [int(i) for i in area_coord.split(',')]
                # Modify the circle coordinates to the rct coordinates.
                rect_x = img_rect['x'] + area_coord[0] - area_coord[2]
                rect_y = img_rect['y'] + area_coord[1] - area_coord[2]
                width = area_coord[2] * 2
                height = width
            # Ignore complex areas, namely the <area> tag with its 'shape' attribute 'poly'.
            else:
                continue

            area_rect = {'x': rect_x, 'y': rect_y, 'width': width, 'height': height}
            outer_html = area_tag.get_attribute('outerHTML')
            outer_html = outer_html.replace('\n', ' ')
            outer_html = outer_html.replace('\r', '')
            area_tag_info_list += [(area_tag, True, [area_rect], outer_html)]

    return area_tag_info_list


def get_onclick_tags(driver: webdriver.Chrome) -> list:
    """
    Get all tags with 'onclick' event attribute.
    Actually, most HTML tags with 'onclick' event attribute are employed to conduct page-jumps like <a> tags.
    Extract the following information:
        1). visibility;
        2). clickable rect;
        3). outerHTML.
    :param driver:
    :return:
    """
    onclick_tag_info_list = list()

    # Get all tags with 'onclick' attribute.
    onclick_tag_list = driver.find_elements(By.XPATH, '//body//*[@onclick]')
    if len(onclick_tag_list) == 0:
        return onclick_tag_info_list
    print("\tThe number of 'onclick' tags is %d." % len(onclick_tag_list))

    # Extract the required information.
    for onclick_tag in onclick_tag_list:
        try:
            rect_list = list()
            is_visible = onclick_tag.is_displayed()
            if is_visible:
                rect_list += [onclick_tag.rect]
            outer_html = onclick_tag.get_attribute('outerHTML')
            outer_html = outer_html.replace('\n', ' ')
            outer_html = outer_html.replace('\r', '')
            onclick_tag_info_list += [(onclick_tag, is_visible, rect_list, outer_html)]
        except StaleElementReferenceException:
            continue

    return onclick_tag_info_list


def get_iframe_tags(driver: webdriver.Chrome) -> list:
    """
    Get all <iframe> tags and <frame> tags, and extract the basic information.
    Do not consider the inner HTML code of <iframe> tags here.
    The processing of the inner HTML of each <iframe> tag is left to the 'switch_to_iframe' function.
    Notably, some <iframe> (or <frame>) tags are placed out of the <body> tag.
    Besides, in certain cases, the HTML page has no <body> tag. That is, such pages have only <head> tags and <iframe> (or <frameset>) tags.
    Extract the following information:
        1). visibility;
        2). clickable rect;
        3). outerHTML.
    :param driver:
    :return:
    """
    iframe_tag_info_list = list()

    # Get all <iframe> (or <frame>) tags.
    iframe_tag_list = driver.find_elements(By.XPATH, '//iframe')
    frame_tag_list = driver.find_elements(By.XPATH, '//frame')
    iframe_tag_list += frame_tag_list
    if len(iframe_tag_list) == 0:
        return iframe_tag_info_list
    print("\tThe number of <iframe> (or <frame>) tags is %d." % len(iframe_tag_list))

    # Extract the information.
    for iframe_tag in iframe_tag_list:
        try:
            rect_list = list()
            is_visible = iframe_tag.is_displayed()
            if is_visible:
                rect_list += [iframe_tag.rect]
            outer_html = iframe_tag.get_attribute('outerHTML')
            outer_html = outer_html.replace('\n', ' ')
            outer_html = outer_html.replace('\r', '')
            iframe_tag_info_list += [(iframe_tag, is_visible, rect_list, outer_html)]
        except StaleElementReferenceException:
            continue

    return iframe_tag_info_list


def switch_to_iframe(driver: webdriver.Chrome, iframe_obj: WebElement, iframe_id: int, current_dir: str) -> None:
    """
    Switch from the current frame to the target inner sub-frame.
    This function focuses on processing the inner HTML code of each <iframe> (or <frame>) tag.

    Note that, multiple webpage may employ nested <iframe> (or <frame>) tags.
    For example, a webpage contains an <iframe> tag, notated as iframe_0.
    The inner HTML code of iframe_0 contains another <iframe> tag, notated as iframe_0_0.
    ...

    Therefore, the emphasis of this script is on how to process the nested <iframe> (or <frame>) tags.
    Actually, the inner HTML code of each <iframe> (or <frame>) tag should be treated as an individual webpage.
    As what we have done in the main frame, we should extract the interaction tags in each <iframe> (or <frame>) tag.

    Notably, one cannot get the attribute of the current <iframe> tag after switching to it.
    :param driver:
    :param iframe_obj:
    :param iframe_id:
    :param current_dir:
    :return:
    """
    # Create iframe directory to save the iframe info.
    cur_iframe_dir = 'iframe_' + str(iframe_id)
    cur_iframe_dir = os.path.join(current_dir, cur_iframe_dir)
    if os.path.exists(cur_iframe_dir):
        shutil.rmtree(cur_iframe_dir)
    os.mkdir(cur_iframe_dir)

    # Switch the webdriver to the target sub-iframe.
    driver.switch_to.frame(iframe_obj)

    # Extract the required info.
    a_info_list = get_a_tags(driver)
    area_info_list = get_area_tags(driver)
    onclick_info_list = get_onclick_tags(driver)
    iframe_info_list = get_iframe_tags(driver)

    # Save the extracted info.
    save_tag_info(a_info_list, 'a', cur_iframe_dir)
    save_tag_info(area_info_list, 'area', cur_iframe_dir)
    save_tag_info(onclick_info_list, 'onclick', cur_iframe_dir)
    save_tag_info(iframe_info_list, 'iframe', cur_iframe_dir)

    # Save the HTML code of the current frame.
    html_file = 'page_source.html'
    html_file = os.path.join(cur_iframe_dir, html_file)
    with open(html_file, 'w', encoding='utf-8') as fw:
        fw.write(driver.page_source)

    # Determine whether there are any sub-frames.
    if iframe_info_list:
        print("\t--------------- Switch to the sub-frames ---------------")
        for i, iframe_info in enumerate(iframe_info_list):
            # There is no need to switch to the invisible frames.
            if not iframe_info[1]:
                continue
            print("\tParsing sub-iframe-%d ..." % i)
            sub_iframe_obj = iframe_info[0]
            # Switch to the sub-frame.
            switch_to_iframe(driver, sub_iframe_obj, i, cur_iframe_dir)

    # Switch back to the parent frame.
    driver.switch_to.parent_frame()


def save_tag_info(tag_info_list: list, tag_type: str, save_dir: str) -> None:
    """
    Given the extracted tag info, dump them into the corresponding sample directory.
    Each tag info is represented as a tuple like (tag_element_obj, visibility, click_rect_list, outerHTML).
    This function should extract and reserve the following info:
        1). tag ID;
        2). tag type;
        3). visibility;
        4). clickable rect list;
        5). outer HTML code.
    Here, tag ID can be represented as the combination of tag type and the corresponding sequence number.
    For example, the ID of the first <a> tag can be represented as 'a_0'.
    :param tag_info_list: [(tag_obj, bool, [dict, dict, ...], str), ...]
    :param tag_type: 'a', 'area', 'onclick', or 'iframe'
    :param save_dir:
    :return:
    """
    # The prefix of each tag ID (e.g., the prefix of 'a_0' os 'a_').
    id_prefix = ''
    if tag_type == 'a':
        id_prefix = 'a_'
    elif tag_type == 'area':
        id_prefix = 'area_'
    elif tag_type == 'onclick':
        id_prefix = 'onclick_'
    else:
        id_prefix = 'iframe_'

    save_info_str = ''
    for i, info in enumerate(tag_info_list):
        id_str = id_prefix + str(i)
        # Ignore the first element of the info (tag_obj).
        is_visible = str(int(info[1]))
        rect = str(info[2])
        outer_html = info[3]
        # Merge the info into one string.
        save_info_str += '\t'.join([id_str, is_visible, rect, outer_html]) + '\n'

    file_name = os.path.join(save_dir, 'redirection_tags.txt')
    with open(file_name, 'a', encoding='utf-8') as fw:
        fw.write(save_info_str)

