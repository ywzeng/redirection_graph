# -*-coding: utf-8 -*-

"""
@author: zyw
@file  : crawler.py
@date  : 2024/1/23
"""
import datetime
import time
import os
import shutil
import json
import href_extraction as he

from selenium import webdriver
from datetime import datetime
from pprint import pprint
from general_funcs import save_tag_info


def chrome_crawler(driver_path: str, tar_domain: str, save_dir: str, wait_time: int = 30, headless: bool = False) -> bool:
    """
    Run this func every day to capture redirection fluxing cases.
    Crawl the given URLs through Chrome driver, and get the corresponding info.
    :param driver_path:
    :param tar_domain:
    :param save_dir: sample directory.
    :param wait_time:
    :param headless:
    :return:
    """
    is_crashed = False

    opts = webdriver.ChromeOptions()
    opts.add_argument('--no-sandbox')                                   # Disable sandbox
    opts.add_argument('--incognito')                                    # Start in incognito (stealth) mode.
    opts.add_argument('--disable-web-security')                         # Disable the same-origin policy.
    opts.add_argument('--test-type --ignore-certificate-errors')        # Ignore certificate errors.
    if headless:        # Check the headless mode should be enabled.
        opts.add_argument('--headless')
    # Disable the info-bar that says 'Chrome is being controlled...'.
    opts.add_experimental_option(name='excludeSwitches', value=['enable-automation'])
    # Enable the performance log.
    opts.set_capability(name='goog:loggingPrefs', value={'browser': 'ALL', 'performance': 'ALL'})

    # Set Chrome driver path. Driver should be loaded by 'service' in Selenium >= 4.6.
    service = webdriver.ChromeService(executable_path=driver_path)
    driver = webdriver.Chrome(options=opts, service=service)
    driver.set_window_size(width=1680, height=1050)

    try:
        start_url = tar_domain
        if tar_domain[:7] != 'http://' or tar_domain[:8] != 'https://':
            start_url = 'http://' + tar_domain + '/'
        print("Crawling %s ..." % start_url)
        start_time = int(time.time())     # Second.
        driver.get(start_url)
        time.sleep(wait_time)

        # Extract the tag info.
        a_info_list = he.get_a_tags(driver)
        area_info_list = he.get_area_tags(driver)
        onclick_info_list = he.get_onclick_tags(driver)
        iframe_info_list = he.get_iframe_tags(driver)

        # Create the sample directory. Append the timestamp
        dt = datetime.now()
        dt_str = '-'.join(['{:0>4s}'.format(str(dt.year)), '{:0>2s}'.format(str(dt.month)), '{:0>2s}'.format(str(dt.day)),
                           '{:0>2s}'.format(str(dt.hour)), '{:0>2s}'.format(str(dt.minute)), '{:0>2s}'.format(str(dt.second))])
        # Use this tag to distinguish samples with the same start domain name.
        sample_tag = tar_domain + '_' + dt_str
        sample_dir = os.path.join(save_dir, sample_tag)
        # If the directory exists, recreate it.
        if os.path.exists(sample_dir):
            shutil.rmtree(sample_dir)
        os.mkdir(sample_dir)

        # Save the screenshot.
        screen_path = os.path.join(sample_dir, 'screenshot.png')
        driver.get_screenshot_as_file(screen_path)

        # Save the clickable tag info.
        save_tag_info(a_info_list, 'a', sample_dir)
        save_tag_info(area_info_list, 'area', sample_dir)
        save_tag_info(onclick_info_list, 'onclick', sample_dir)
        save_tag_info(iframe_info_list, 'iframe', sample_dir)

        # Check whether there are nested sub-iframes.
        if iframe_info_list:
            print("\t--------------- Into the sub-iframes ---------------")
            for i, iframe_info in enumerate(iframe_info_list):
                # Ignore the invisible iframes here.
                if not iframe_info[1]:
                    continue
                print("\tParsing iframe-%d ..." % i)
                cur_iframe_obj = iframe_info[0]
                he.switch_to_iframe(driver, cur_iframe_obj, i, sample_dir)

        # Get the performance log.
        entry_list = driver.get_log('performance')
        performance_log_path = os.path.join(sample_dir, 'performance_log.txt')
        with open(performance_log_path, 'w', encoding='utf-8') as fw:
            for entry in entry_list:
                fw.write(str(entry) + '\n')

        # Get the response body log.
        response_list = list()
        for entry in entry_list:
            timestamp = entry['timestamp']
            message = json.loads(entry['message'])['message']

            # Extract the response body.
            if message['method'] == 'Network.responseReceived':
                request_id = message['params']['requestId']
                # Ignore the invalid requestID (with not response).
                try:
                    response_body = driver.execute_cdp_cmd('Network.getResponseBody', {'requestId': request_id})
                    response_body['requestId'] = request_id
                    response_body['timestamp'] = timestamp
                    response_list += [response_body]
                except:     # Ignore the cases that have not found the matched requestId.
                    continue
        # Save the response body log.
        response_log_path = os.path.join(sample_dir, 'response_log.txt')
        with open(response_log_path, 'w', encoding='utf-8') as fw:
            for response_body in response_list:
                fw.write(str(response_body) + '\n')

        # Get the HTML source of the current page.
        html_path = os.path.join(sample_dir, 'page_source.html')
        with open(html_path, 'w', encoding='utf-8') as fw:
            fw.write(driver.page_source)

        # Get the metadata of the current crawling.
        end_url = driver.current_url
        end_title = driver.title
        end_time = int(time.time())       # Second.
        cost_time = end_time - start_time
        metadata = [tar_domain, sample_tag, str(int(start_time)), str(int(end_time)), str(cost_time), start_url, end_url, end_title]

        metadata_file = os.path.join(os.path.abspath('data'), 'cur_samples.txt')
        with open(metadata_file, 'a', encoding='utf-8') as fw:
            metadata_str = '\t'.join(metadata) + '\n'
            fw.write(metadata_str)
        print('Cost time: %s(s)\n' % cost_time)

    except Exception as exception:
        print('Got an exception: %s' % exception)
        print('Stuck at crawling %s ...' % tar_domain)
        is_crashed = True
        # Log the corresponding info if the driver is crashed.
        cur_exception = str(exception)
        crash_entry = [tar_domain, cur_exception]
        failure_file = os.path.join(os.path.abspath('data'), 'failure_samples.txt')
        with open(failure_file, 'a', encoding='utf-8') as fw:
            crash_str = '\t'.join(crash_entry) + '\n'
            fw.write(crash_str)

    finally:
        driver.close()
        driver.service.stop()
        # driver.quit()
        return False if is_crashed else True


if __name__ == "__main__":
    chrome_driver_path = r'chromedriver.exe'
    sample_save_dir = r"E:\redirection_samples\xinda"
    domain = 'jjc37.com'     # www.01qxqx.com; 02qxqx.com; 01bxbx.com; jjc37.com
    chrome_crawler(chrome_driver_path, domain, sample_save_dir, 30)
