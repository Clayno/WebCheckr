#!/usr/bin/python3
# coding: utf-8

import sys
import os
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import threading
import argparse
import os
import base64
import asyncio
import aiohttp
import traceback
import multiprocessing
import logging
from tqdm import tqdm
from multiprocessing.pool import ThreadPool
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed, FIRST_COMPLETED
from urllib.parse import urlparse
from time import sleep
# Custom modules
from modules.credscheckr import CredsCheckrModule
from modules.wappalyzer import WappalyzerModule
from modules.dirsearch import DirsearchModule
from modules.cvesearch import cve_search_start, query_cve
from modules.selenium import selenium_start, SeleniumModule
from helpers.cprint import Cprinter
from helpers.dockers import remove_container, docker_wrapper, cleanup_webcheckr_dockers
from helpers.urls import nmap_retrieve, validate_url, url_sanitize
from report.report import cve_to_html, write_html

# List of class check
checks = []

# Class containing data for a check
class Check:
    def __init__(self, hostname, directory, screen_path, 
            screen_content, title, cve, modules):
        self.hostname = hostname
        self.directory = directory
        self.screen_path = screen_path
        self.screen_content = screen_content
        self.title = title
        self.cve = cve
        self.modules = modules

    def to_string(self):    
        return "Not Yet"
        """
        final = "[+] Scan report for {0}\n".format(self.hostname)
        if self.wappalyzer.result == None or not self.wappalyzer.result:
            final += "Nothing found\n"
            return final
        for category, l in self.wappalyzer.result.items():
            final += '|----{0}:\n'.format(category)
            for tech in l:
                name, version = tech.split(':', 1)
                if version == "" or not version or version=="None":
                    final += '|        {0}\n'.format(name)
                else:
                    if self.cve and name in self.cve:
                        warning_msg  = '| {nb_cve} vulnerabilities and {nb_crit_vuln} with a cvss > 7.5'.format(name=name, version=self.cve[name]['version'], nb_cve=self.cve[name]['number_cve'], nb_crit_vuln=self.cve[name]['number_critical_cve'])
                        final += '|        {0} ({1}) {2}\n'.format(name, version, warning_msg)
                    else:
                         final += '|        {0} ({1})\n'.format(name, version)
        if "CMS" in self.wappalyzer.result.keys():
            cms = [cms.split(':', 1)[0] for cms in self.wappalyzer.result["CMS"]]
        else:
            cms = None
        # Check if a known CMS is detected
        if cms is not None:   
            final += "\n[i] {0} found !".format(cms[0])
        final += "\n"
        return final"""

    def from_json(self, json):
        self.__dict__.update(json)        


def print_banner():
    print(
        '''
 __    __     _       ___ _               _         
/ / /\ \ \___| |__   / __\ |__   ___  ___| | ___ __ 
\ \/  \/ / _ \ '_ \ / /  | '_ \ / _ \/ __| |/ / '__|
 \  /\  /  __/ |_) / /___| | | |  __/ (__|   <| |   
  \/  \/ \___|_.__/\____/|_| |_|\___|\___|_|\_\_|   
                                                               
    WebCheckr - Initial check for web pentests.
    '''
    )


def init_logging(verbose=False, debug=False, logfile=None):
    # Set up our logging object
    logger = logging.getLogger('webcheckr')

    if debug:
        logger.setLevel(logging.DEBUG)
    elif verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    if logfile:
        # Create file handler which logs even debug messages
        #######################################################################
        fh = logging.FileHandler(logfile)

        # create formatter and add it to the handler
        formatter = logging.Formatter(
            '[%(asctime)s][%(module)s][%(funcName)s][%(levelname)s] %(message)s')
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    # Set up the StreamHandler so we can write to the console
    ###########################################################################
    #formatter = logging.Formatter('[%(asctime)s][%(module)s][%(funcName)s] %(message)s', datefmt='%H:%M:%S')

    #streamHandler = logging.StreamHandler(sys.stdout)
    #streamHandler.setFormatter(formatter)
    #logger.addHandler(streamHandler)

    return logger

def selenium_workflow(url, directory, dirsearch):
    class SeleniumThreadExecutor:
        def __init__(self, thread_num):
            self.results = []
            self.pool = ThreadPool(thread_num)

        def callback(self, result):
            # Get modules results
            if result is not None:
                self.results.append(result)

        def schedule(self, function, args=()):
            self.pool.apply_async(function, args=args, callback=self.callback)

        def wait(self):
            self.pool.close()
            self.pool.join()

        def terminate(self):
            self.pool.terminate()
    
    try:
        driver, container = selenium_start()
        try:
            modules = []
            #credentials_filename = '/webcheckr/data/creds.lst'
            selenium_module = SeleniumModule(url, directory, driver, cprinter)
            #credscheckr_module = CredsCheckrModule(url, credentials_filename, 
            #        container.name, 4444, cprinter)
            modules.append(selenium_module)
            #modules.append(credscheckr_module)
            if dirsearch:
                dirsearch_module = DirsearchModule(url, directory, cprinter)
                modules.append(dirsearch_module)
            executor = SeleniumThreadExecutor(5)
            # Schedule all the tasks to do with Selenium
            for module in modules:
                executor.schedule(module.run)
            executor.wait()
        except:
            traceback.print_exc()
            if executor is not None:
                executor.terminate()
        cprinter.logger.info(f"[{url}] Selenium workflow ended") 
        driver.close()
    except Exception as e:
        traceback.print_exc()
        if container:
            remove_container(container)
    finally:
        if container:
            remove_container(container)
    return executor.results


async def request_async(executor, query_cve, url, name, 
                    version, cve_search, directory, cprinter):
    '''
    Workaround in analyze_found to launch threads.
    '''
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(executor, query_cve, url, name, 
                    version, cve_search, directory, cprinter)

async def analyze_found(url, found, cms_scan, directory, executor):
    '''
    Print and launch a cve-search for all the valid element in found.
    An element is valid if a version is determined alongside the technology.
    Also start the corresponding CMS scanner if one has been detected and the
    option is activated.

    Args:
        found (list): list of technologies found
        cms_scan (boolean): true start scan, false don't
    '''
    try:
        # Maybe not for all the tech, we don't care about css,...
        # https://www.wappalyzer.com/docs/categories
        cprinter.logger.info(f'[{url}] Starting analyzing for CVEs') 
        for_return = {}
        loop = asyncio.get_running_loop()
        future_vulns = []     
        for category, l in found.items():
            for tech in l:
                name, version = tech.split(':', 1)
                if version and version!="None" and version != "":
                    future_vulns.append(request_async(executor, query_cve, url, name, 
                        version, cve_search, directory, cprinter))
        results = await asyncio.gather(*future_vulns)
        results_parsed = {}
        for task in results:
            if task:
                results_parsed[task.get('name')] = task
        for category, l in found.items():
            cprinter.cprint(string='|----{0}:'.format(category), url=url)
            for tech in l:
                name, version = tech.split(':', 1)
                if not version or version=="None" or version=="":
                    cprinter.cprint('|        {0}'.format(name), url=url)
                else:
                    vuln = results_parsed.get(name.lower())
                    if vuln != None:
                        warning_msg = '\033[0;31m{nb_cve} vulnerabilities and {nb_crit_vuln} with a cvss > 7.5\033[0m'.format(nb_cve=vuln['number_cve'],  nb_crit_vuln=vuln['number_critical_cve'])
                        cprinter.cprint(f'[+] [{url}]        {name} ({version}) {warning_msg}', filename='', print_stdout=True)
                        cprinter.cprint(f'|        {name} ({version}) \033[0;31m{warning_msg}\033[0m', url=url)
                        for_return[name] = vuln
                    else:
                        cprinter.cprint(f'|        {name} ({version})', url=url)
        if "CMS" in found.keys():
            cms = [cms.split(':', 1)[0] for cms in found["CMS"]]
        else:
            cms = None
        # Check if a known CMS is detected
        if cms is not None:   
            cprinter.found(f"{cms[0]} found !", url=url)
        return for_return
    except:
        traceback.print_exc()

async def check_workflow(url, cms_scan, cve_check, dirsearch, directory):
    try:
        # Initialize modules
        wappalyzer_module = WappalyzerModule(url, cprinter.logger)
        modules = []
        executor = ThreadPoolExecutor(20)
        loop = asyncio.get_running_loop()
        future_selenium = loop.run_in_executor(executor, selenium_workflow, url, directory, 
                dirsearch)
        # Start analyzing web application
        found = await loop.run_in_executor(executor, wappalyzer_module.run)
        # Gathering results from modules
        wap_module_result = wappalyzer_module.get_result()
        modules.append(wap_module_result)
        if wap_module_result['content'] == None:
            cprinter.logger.info(f'[{url}] No content from wappalyzer')
            cprinter.cprint(f"[x][{url}] Couldn't get any technologies",
                    filename='', 
                    print_stdout=True)
            vulns = None
        else:
            if not cve_check:
                cprinter.logger.info(f'[{url}] No cve check')
                vulns = None
            else:
                cprinter.logger.info(f'[{url}] cve check chosen')
                found = wap_module_result['content'] 
                # Analyze the foundings by Wappalyzer and start CMS scan if asked
                vulns = await analyze_found(url, found, cms_scan, directory, executor)
                # Gathering result from modules
                #modules.append(vulns.result())
                cprinter.logger.info(f"[{url}] vulns done")
        cprinter.logger.info(f'[{url}] Waiting for selenium workflow to end')
        selenium_workflow_results = await future_selenium
        for result in selenium_workflow_results:
            if result['name'] == 'selenium':
                selenium_results = result['content']
            else:
                # Gathering result from modules
                modules.append(result)
        screen_path = selenium_results['screenshot_path']
        title = selenium_results['title']
        screen_content = selenium_results['screenshot']
        cprinter.logger.debug(f'[{url}] {selenium_workflow_results}')
        cprinter.logger.info(f'[{url}] Creating Check object')
        check = Check(url, directory, screen_path, screen_content, title, vulns, modules) 
        return check
    except:
        cprinter.logger.exception()
        traceback.print_exc()

def check_website(url, cms_scan, cve_check, dirsearch, progress_file_lock, counter):
    try:
        cprinter.logger.info(f'[{url}] Started scanning')
        cprinter.info(string="Started scanning", url=url)
        # Getting hostname to create report file    
        parsed_url = urlparse(url)
        directory = os.path.join(base_dir, parsed_url.netloc)
        if not os.path.exists(directory):
            os.makedirs(directory)
        screen_path = None
        title = None
        container = None
        loop = asyncio.new_event_loop()
        check = loop.run_until_complete(check_workflow(url, cms_scan, cve_check, dirsearch, 
            directory))
        cprinter.logger.info(f'[{url}] Scan is over')
        cprinter.info('Workflow is over', url=url)
        with progress_file_lock:
            print(check.__dict__, file=open("{base_dir}/.webcheckr".format(base_dir=base_dir), 'a'))
        return check
    except:
        cprinter.logger.exception()
        traceback.print_exc()


def finished_check(result):
    '''
    Callback function for finished checks.
    '''
    try:
        cprinter.logger.debug(f'callback {result}')
        checks.append(result)
        pbar.update()
        counter.value += 1
    except Exception as e:
        cprinter.logger.error(e)

def init(arg1, arg2, arg3):
    '''
    Initiate processes with useful globals.
    '''
    global pbar
    global counter
    global cprinter
    pbar = arg1
    counter = arg2
    cprinter = arg3

if __name__ == "__main__":
    parser  = argparse.ArgumentParser(description="WebCheckr - Initial check for web pentests")
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output in log file')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output in log file')
    parser.add_argument('-b', '--directory_bf', action='store_true', help='Launch directory bruteforce with provided wordlist. File has to be in current directory, docker reasons.', default=False)
    parser.add_argument('-l', '--launch_cve_docker', action='store_true', help='Launch cve-search docker. To start it manually: docker start cvesearch_docker')
    parser.add_argument('-n', '--no_cve_check', action='store_true', help='Do not ceck cves for the technologies found')
    parser.add_argument('-c', '--cms_scan', action='store_true', help='Launch CMS scanner if detected. Supported: Wordpress, Joomla, Drupal')
    parser.add_argument('-t', '--timeout', action='store', help='Timeout used to validate urls in seconds', default=20)
    parser.add_argument('-w', '--concurrent_targets', action='store', help='Number of concurrent targets to scan', default=5)
    parser.add_argument('-o', '--output_dir', action='store', help='Output dir as relative path')
    group_urls = parser.add_mutually_exclusive_group(required=True)
    group_urls.add_argument('-U', '--urls_file', action='store', help='Provide file instead of url, one per line. File has to be in current directory, docker reasons.')
    group_urls.add_argument('-u', '--url', help="URL of target site")
    group_urls.add_argument('-i', '--nmap_file', action='store', help='Provide XML nmap report with or instead of urls. This will launch the script to every http/https service found. File has to be in current directory, docker reasons.')
    args = parser.parse_args()
    # Arguments
    docker_path = 'shared'
    url =  args.url
    directory_bf = args.directory_bf
    urls_file = None
    if args.urls_file:
        urls_file = os.path.join(docker_path, args.urls_file)
    launch_cve_docker = args.launch_cve_docker
    cve_check = not args.no_cve_check
    cms_scan = args.cms_scan
    nmap_file = None
    if args.nmap_file:
        nmap_file = os.path.join(docker_path, args.nmap_file)
    concurrent_targets = int(args.concurrent_targets)
    timeout = int(args.timeout)
    directory = args.output_dir if args.output_dir else 'results'
    base_dir = os.path.join(os.getcwd(), docker_path,  directory)
    verbose = args.verbose
    debug = args.debug
    logfile = f'{base_dir}/webcheckr.log'
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)
    logger = init_logging(verbose=verbose, debug=debug, logfile=logfile)
    # L33t banner
    print_banner()
    # Sanitize the list of urls
    loop = asyncio.get_event_loop()
    urls = loop.run_until_complete(url_sanitize(urls_file, url, nmap_file, timeout))
    for url in urls:
        logger.info(url)
        print(url)
    nb_urls = len(urls)
    checks = []
    manager = multiprocessing.Manager()
    progress_file_lock = manager.Lock()
    counter = manager.Value('i', 0)
    # Handling the dockers with care, if something crashes, we need to stop all of them
    try:
        # Start cve-search docker
        if cve_check:
            cve_search = cve_search_start(launch_cve_docker)
        print('[+] Starting checking') 
        pbar = tqdm(total=nb_urls, desc='Progress', position=1)
        cprinter = Cprinter(base_dir, pbar, counter, logger)
        try:
            with multiprocessing.Pool(concurrent_targets, initializer=init, 
                    initargs=(pbar, counter, cprinter, )) as pool:
                for url in urls:
                    pool.apply_async(check_website, 
                            args=(url, cms_scan, cve_check, directory_bf, progress_file_lock, 
                                counter,),
                            callback=finished_check)
                pool.close()
                pool.join()
        except Exception as e:
            cprinter.logger.error(e)
            pool.terminate()
        # Output the results
        pbar.close()
        cprinter.logger.info("Checks finished")
        cprinter.logger.debug(checks)
        #print()
        #for check in checks:
        #    if check:
        #        print(check.to_string())
        # Write html report
        to_write = write_html(base_dir, checks)
        print("[+] Html report written to report.html")
    except:
        traceback.print_exc()
    finally:
        print("Shutting down every containers...")
        if launch_cve_docker:
            remove_container(cve_search)
        cleanup_webcheckr_dockers()
