#!/usr/bin/python3
# coding: utf-8

import sys
import os
import docker
import json
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import threading
import argparse
import os
import base64
from urllib.parse import urlparse
from time import sleep
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
import asyncio
import aiohttp
from concurrent.futures import ProcessPoolExecutor, as_completed, FIRST_COMPLETED


# Docker images installed and used
images = {
        "Wappalyzer": "wappalyzer/cli",
        "Wpscan": "wpscanteam/wpscan",
        "Gobuster": "kodisha/gobuster",
        "Joomscan": "pgrund/joomscan",
        "Drupwn": "immunit/drupwn",
        "CVE-search": "ttimasdf/cve-search:withdb",
        "Selenium": "selenium/standalone-chrome",
        "Changeme": "ztgrace/changeme",
        "Dirhunt": "layno/dirhunt"
        }

# Commands given to dockers
commands = {
        "Wpscan": "--url {0} --no-banner -f cli-no-colour",
        "Joomscan": "--url {0}",
        "Drupwn": "enum {0}",
        "CVE-search": "{0}",
        "Wappalyzer": "{0}",
        "Wappalyzer_recursive": "{0} --recursive=1",
        "Gobuster": "-fw -w {0} -u {1} -k -q",
        "Selenium": "",
        "Changeme": "{0}",
        "Dirhunt": "{0}"
        }

# CMS for which we have scanners
scanners = {
        "WordPress": "Wpscan",
        "Joomla": "Joomscan",
        "Drupal": "Drupwn"
        }

# List of dockers id
docker_ids = []

# List of threads
threads = []

# List of class check
checks = []

# Template of report
report = '''<!DOCTYPE html>
<html>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<head>
<style>
body{{
    font-family: "Arial";
}}

h2{{
    color: black;
}}

.content{{
    position: static;
    overflow: hidden;
    border: 1px solid rgb(204, 204, 204);
    border-radius: 5px;
    padding: 0.01em 16px;
}}

.screenshot{{
    position: static;
    float: right;
    max-width:30%;
    max-height:30%;
}}

</style>
<title>WebCheckr Report</title>
</head>
<body>

{0}

</body>
<script>
function togglediv(id) {{
    var div = document.getElementById(id);
    div.style.display = div.style.display == "none" ? "block" : "none";
    }}
</script>
</html>'''


# Class containing data for a check
class Check:
    def __init__(self, hostname, directory, screen_path, 
            title, wappalyzer, cve):
        self.hostname = hostname
        self.directory = directory
        self.screen_path = screen_path
        self.title = title
        self.wappalyzer = wappalyzer
        self.cve = cve

    def to_string(self):
        final = "[+] Scan report for {0}\n".format(self.hostname)
        if self.wappalyzer == None:
            return "Nothing found"
        for category, l in self.wappalyzer.items():
            final += '|----{0}:\n'.format(category)
            for tech in l:
                name, version = tech.split(':', 1)
                if version == "":
                    final += '|        {0}\n'.format(name)
                else:
                    if name in self.cve:
                        final += '|        {0} ({1}) {2}\n'.format(name, version, self.cve[name][1])
                    else:
                         final += '|        {0} ({1})\n'.format(name, version)
        if "CMS" in self.wappalyzer.keys():
            cms = [cms.split(':', 1)[0] for cms in self.wappalyzer["CMS"]]
        else:
            cms = None
        # Check if a known CMS is detected
        if cms is not None:   
            final += "\n[i] {0} found !".format(cms[0])
        final += "\n"
        return final

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


def docker_wrapper(image, command, directory, **kwargs):
    client = docker.from_env()
    container = client.containers.run(image,
            command, detach=True, auto_remove=True, **kwargs)
    for line in container.logs(stream=True):
            print_and_report(line.decode().strip(), "dirhunt.txt", directory=directory)
    return container

def wappalyzer(url):
    """
    Launch Wappalyzer docker for the specified URL.

    Args:
        url (str): URL to analyse

    Returns:
        None if Wappalyzer doesn't work
        Dict of found technologies otherwise
    """
    try: 
        client = docker.from_env()
        container = client.containers.run(images["Wappalyzer"], 
                commands["Wappalyzer_recursive"].format(url),
                detach=True, auto_remove=True)
        response = ""
        for line in container.logs(stream=True):
            response += line.decode()
        # Sometimes, Wappalyzer doesn't work in recursive mode :'(
        try:
            response = json.loads(response)
        except:
            container = client.containers.run(images["Wappalyzer"], 
                commands["Wappalyzer"].format(url),
                detach=True, auto_remove=True)
            response = ""
            for line in container.logs(stream=True):
                response += line.decode()
            # Now we have to parse the JSON response
            try:
                response = json.loads(response)
            except:
                # If we can't parse it, means nothing was found !
                return None
        applications = response['applications']
        # Converting json into dict => found
        found = {}
        for cell in applications:
            key = ''.join(v for v in cell['categories'][0].values())
            data = '{0}:{1}'.format(cell['name'], cell['version'])
            if key in found:
                found[key].append(data)
            else:
                found[key] = [data]
        return found
    finally:
        remove_container(container)


def cms_scanner(url, scanner, directory):
    """
    Launch the scanner for the found CMS on the url.

    Args:
        url (str): URL to scan
        scanner (str): CMS scanner
    """
    print_and_report("[+] Launching {0}".format(scanner))
    try:
        client = docker.from_env()
        container = client.containers.run(images[scanner], commands[scanner].format(url), 
                detach=True, auto_remove=True)
        docker_ids.append(container)
        for line in container.logs(stream=True):
            print_and_report(line.decode().strip(), "{0}.txt".format(scanner), directory=directory)
    finally:
        remove_container(container)

def gobuster(url, wordlist, directory):
    """
    Launch Gobuster docker.

    Args:
        url (str): URL to bruteforce
    """
    print("[i] Bruteforcing directories/files in background")
    path, filename = os.path.split(wordlist)
    try:
        # Directory bruteforce with force wildcards without checking certificate
        command = commands["Gobuster"].format("/wordlists/".format(filename), url)
        client = docker.from_env()
        container = client.containers.run(images["Gobuster"], command, detach=True,
                volumes={path: {'bind': '/wordlists', 'mode': 'ro'}},
                auto_remove=True)
        docker_ids.append(container)
        for line in container.logs(stream=True):
            print_and_report(line.decode().strip(), "gobuster.txt", directory=directory)
    except:
        remove_container(container)

def cve_search_start(no_launch):
    """
    Starts the CVE-search docker.

    Args:
        no_launch (boolean): true start a docker, false get the one running

    Returns:
        Container of cvesearch docker
    """
    if no_launch:
            container = docker.from_env().containers.get('cvesearch')
    else:
        print("[i] Starting the CVE-search docker, this may take some time...")
        # Count 5~10min to start
        command = "" 
        client = docker.from_env()
        container = client.containers.get('cvesearch')
        container.start()
        #container = client.containers.run(images["CVE-search"], command,
        #        ports={5000: ('127.0.0.1', 5000)} ,detach=True)
    print("[i] Checking if container is up...")
    while True:
        try:
            response = requests.get("http://127.0.0.1:5000").status_code
            if response == 200:
                break
        except:
            pass
        sleep(2)
    return container

def query_cve(name, version, container, directory):
    """
    Runs a search in the CVE-search container.

    Args:
        name (str): Name of the technology to analyse
        version (str): Version of the technology to analyse
        container: CVE-search container
    """
    filename = 'cve_search_{0}_{1}.txt'.format(name, version)
    name = name.lower().replace(" ", ":")
    command = "search.py -p '{0}:{1}' -o json".format(name, version)
    exit_code, output = container.exec_run(command)
    vulns = {
                'total': 0,
                'critical': 0
            }
    if output == None:
        pass
    else:
        output = output.decode().split('\n')
        response = [json.loads(i) for i in output if i is not None and i != '']
        for vuln in response:
            print_and_report('CVE   : {0}'.format(vuln['id']), filename, directory=directory)
            print_and_report('DATE  : {0}'.format(vuln['Published']), filename, directory=directory)
            print_and_report('CVSS  : {0}'.format(vuln['cvss']), filename, directory=directory)
            print_and_report('{0}'.format(vuln['summary']), filename, directory=directory)
            print_and_report('\n', filename, directory=directory)
            print_and_report('References:\n-----------------------\n', filename, directory=directory)
            for url in vuln['references']:
                print_and_report(url, filename, directory=directory)
            print_and_report('\n', filename, directory=directory)
            vulns['total'] += 1
            if float(vuln['cvss']) > 7.5:
                vulns['critical'] += 1
        if vulns['total'] != 0:
            return '{0} vulnerabilities and {1} with a cvss > 7.5'.format(vulns['total'], 
                    vulns['critical'])
        return None

    
def remove_container(container):
    """
    Safely removes containers.
    """
    try: 
        statuses = ['removed', 'exited', 'dead']
        if container.status not in statuses:
            container.kill()
    except:
        pass

def print_and_report(string='', filename='', directory='', no_print=False):
    """
    Print to output and to file.

    Note:
        If filename is empty, writing to report.txt in the current 
        directory (URL of the target).

    Args:
        string (str): String to print
        filename (str): File to write to
        directory (str): Directory to write to
    """
    if filename == '':
        if not no_print:
            print(string)
        filename = 'report.txt'
    if not os.path.exists(directory):
        os.makedirs(directory)
    filename = "{0}/{1}".format(directory, filename)
    if os.path.exists(filename):
        print(string, file=open(filename, 'a'))
    else:
        print(string, file=open(filename, 'w'))


def nmap_retrieve(nmap_file):
    """
    Parse and retrieve http/https services of a host.

    Args:
        nmap_file (str): Path of the nmap file 

    Returns:
        List of http/https services urls found
    """
    from libnmap.parser import NmapParser
    http_open = []
    nmap = NmapParser.parse_fromfile(nmap_file)
    for host in nmap.hosts:
        for port in host.get_open_ports():
            if port[1] == 'tcp':
                if 'http' in host.get_service(port[0]).service and 'https' not in host.get_service(port[0]).service:
                    if host.hostnames:
                        http_open.append("http://{0}:{1}".format(host.hostnames[0], port[0]))
                    else:
                        http_open.append("http://{0}:{1}".format(host.address, port[0]))
                elif 'https' in host.get_service(port[0]).service:
                    if host.hostnames:
                        http_open.append("https://{0}:{1}".format(host.hostnames[0], port[0]))
                    else:
                        http_open.append("https://{0}:{1}".format(host.address, port[0]))
    return http_open
            

async def validate_url(session, url):
    '''
    Returns url if connectivity went right. With priority on https scheme.
    '''
    responses = await asyncio.gather(session.get(url[0], verify_ssl=False, timeout=10), 
            session.get(url[1], verify_ssl=False, timeout=10), return_exceptions=True)
    if hasattr(responses[1], 'status') and responses[1].status != None:
        return url[1]
    elif hasattr(responses[0], 'status') and responses[0].status != None:
        return url[0]
    return None


async def url_sanitize(urls_file, url, nmap_file):
    """
    Organize all the urls input.
    Check if the list of urls have already been scanned.

    Args:
        urls_file (str): Path to file containing the urls to scan
        url (str): Single url to scan
        nmap_file (str): Path to nmap scan to retrieve urls to scan from
    """
    urls = []
    if urls_file is not None:
        urls = open(urls_file).readlines()
    elif url is not None:
        urls=[url]
    if nmap_file is not None:
        urls.extend(nmap_retrieve(nmap_file))
    urls = [url.strip() for url in urls]
    # Test the urls for connectivity
    to_test = []
    tmp_urls = []
    async with aiohttp.ClientSession() as session:
        for url in urls:
            if '://' not in url: 
                hostname = urlparse('http://'+url).hostname
                tmp_urls.append(('http://{0}'.format(url), 
                    'https://{0}'.format(url)))
                to_test.append(validate_url(session, ('http://{0}'.format(url), 
                    'https://{0}'.format(url))))
            else:
                hostname = urlparse(url).hostname
                tmp_urls.append(('http://{0}'.format(hostname), 
                    'https://{0}'.format(hostname)))
                to_test.append(validate_url(session, ('http://{0}'.format(hostname),
                    'https://{0}'.format(hostname))))  
            if os.path.exists(urlparse(tmp_urls[-1][0]).hostname):
                print("[-] Removing {0} (already scanned)".format(url))
                to_test.pop()
                break
        results = await asyncio.gather(*to_test)   
    final = []
    for i in range(len(to_test)):
        if not results[i]:
            print("[x] Impossible to reach {0}. Removing it...".format(urlparse(tmp_urls[i][0]).hostname))
        else:
            final.append(results[i])
    if len(final) == 0:
        print("[x] No urls provided. Quitting...")
        exit()
    return final

def selenium_start(port):
    try:
        client = docker.from_env()
        container = client.containers.run(images["Selenium"], 
                commands["Selenium"].format(url),
                ports={4444: ('127.0.0.1', port)},
                shm_size="1G", # https://github.com/elgalu/docker-selenium/issues/20
                detach=True, auto_remove=True)
        docker_ids.append(container)
        sleep(8)
        driver = webdriver.Remote("http://127.0.0.1:{0}/wd/hub".format(port), 
                DesiredCapabilities.CHROME)
        driver.implicitly_wait(30)
        return driver, container
    except Exception as e:
        print("slenium_start", e)
        if container:
            remove_container(container)
        return None

def selenium_get(url, directory, driver):
    '''
    Get a screenshot and the title of the landing page.

    Args:
        url (str): Url to fetch

    Returns:
        path of the screenshot
    '''
    try:
        driver.get(url)
        print("\033[0;32m[i] Title: {0}\033[0m".format(driver.title))
        screen = driver.get_screenshot_as_png()
        screen_path = "{0}/{1}.png".format(directory, 
                base64.b64encode(url.encode()).decode())
        open(screen_path, "wb").write(screen)
        return screen_path, driver.title
    except Exception as e:
        print("[!] Couldn't take screenshot {0}".format(str(e)))
        driver.close()
    finally:
        driver.close()


def analyze_found(url, found, cms_scan, directory):
    '''
    Print and launch a cve-search for all the valid element in found.
    An element is valid if a version is determined alongside the technology.
    Also start the corresponding CMS scanner if one has been detected and the
    option is activated.

    Args:
        found (list): list of technologies found
        cms_scan (boolean): true start scan, false don't
    '''
    # Maybe not for all the tech, we don't care about css, jquery,...
    # https://www.wappalyzer.com/docs/categories
    for_return = {}
    for category, l in found.items():
        print_and_report(string='|----{0}:'.format(category), directory=directory, no_print=True)
        for tech in l:
            name, version = tech.split(':', 1)
            if version == "":
                print_and_report('|        {0}'.format(name), directory=directory, no_print=True)
            else:
                vuln = query_cve(name, version, cve_search, directory)
                if vuln != None:
                    print_and_report('|{3}        {0} ({1}) \033[0;31m{2}\033[0m'.format(
                        name, version, vuln, url), directory=directory)
                    for_return[name] = (version,vuln)
                else:
                    print_and_report('|        {0} ({1})'.format(name, version), directory=directory, 
                            no_print=True)
    if "CMS" in found.keys():
        cms = [cms.split(':', 1)[0] for cms in found["CMS"]]
    else:
        cms = None
    # Check if a known CMS is detected
    if cms is not None:   
        print_and_report("\033[0;32m[+] {0} found in {1}!\033[0m".format(cms[0], url), directory=directory)
        print_and_report(directory=directory)
        if cms_scan == True:
            if cms[0] in scanners.keys():
                thread = threading.Thread(target=cms_scanner, 
                        args=(url, scanners[cms[0]], ),)
                threads.append(thread)
                thread.start()
    return for_return

def write_html(checks):
    final = ""
    i = 0
    for check in checks:
        if check is None:
            final += ''
        else:
            final += '''<div class="check">
        <div class="check-title">
            <h2>{url} ({title})</h2>
            <button onclick="togglediv('content{id}')">toggle</button>
        </div>
        <div class="content" id="content{id}">
            <img class="screenshot" src="{screen_path}">
            <p>
            <b>Directory:</b> {directory}</br>
            </p>
            <p class="techologies">
            <b>Technologies found:</b></br>
                {wappalyzer}</br>
            </p>
            <p class="cve">
            <b>CVE found:</b></br>
                {cve}</br>
            </p>
        </div>
    </div>
    </br>
    '''.format(url=check.hostname, directory=check.directory, screen_path=check.screen_path,
                    wappalyzer=found_to_html(check.wappalyzer), cve=check.cve, 
                    id=str(i), title=check.title)
        i+=1
    return final
        
def found_to_html(found):
    if found == None:
        return "Nothing found"
    final = ""
    for category, l in found.items():
        final += '|----{0}:</br>'.format(category)
        for tech in l:
            name, version = tech.split(':', 1)
            if version == "":
                final += '|        {0}</br>'.format(name)
            else:
                final += '|        {0} ({1})</br>'.format(name, version)
    return final


def check_website(url, cms_scan=False, port=5001):     
    print("\n\033[94m[+] Scanning {0}\033[0m".format(url))
    # Getting hostname to create report file    
    hostname = urlparse(url).hostname
    directory = "{0}/{1}".format(os.getcwd(), hostname)
    if not os.path.exists(directory):
        os.makedirs(directory)
    try:
        try:
            driver, container = selenium_start(port)
            # Start the scanning
            # Get basic informations with selenium
            screen_path, title = selenium_get(url, directory, driver)
            #driver.close()
        except:
            pass
        if directory_bf is not None:
            # Starting bruteforce of directory in background
            thread = threading.Thread(target=gobuster, args=(url, directory_bf, ),)
            threads.append(thread)
            thread.start()
        # Start analysing web application
        found = wappalyzer(url)
        #docker_wrapper(images["Dirhunt"], commands["Dirhunt"].format(url), directory)
        if found == None or not found :
            print("[x] Couldn't get any technologies on {url}".format(url=url))
            check = Check(url, directory, screen_path, title, found, None)
        else:
            # Analyze the foundings by Wappalyzer and start CMS scan if asked
            vulns = analyze_found(url, found, cms_scan, directory)
            check = Check(url, directory, screen_path, title, found, vulns)
        return check
    except Exception as e:
        print("check_website", e)
        if container:
            remove_container(container)
        return None
    finally:
        if container:
            remove_container(container)


if __name__ == "__main__":
    parser  = argparse.ArgumentParser(description="WebCheckr - Initial check for web pentests")
    parser.add_argument('-d', '--directory_bf', action='store', help='Launch directory bruteforce with provided wordlist (full path)')
    parser.add_argument('-n', '--no_cve_launch', action='store_true', help='Do not launch cve-search docker, you have to start it manually: docker start cvesearch')
    parser.add_argument('-c', '--cms_scan', action='store_true', help='Launch CMS scanner if detected. Supported: Wordpress, Joomla, Drupal')
    parser.add_argument('-t', '--concurrent_targets', action='store', help='Number of concurrent targets to scan')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-U', '--urls_file', action='store', help='Provide file instead of url, one per line')
    group.add_argument('-u', '--url', help="URL of target site")
    group.add_argument('-i', '--nmap_file', action='store', help='Provide XML nmap report with or instead of urls. This will launch the script to every http/https service found')
    args = parser.parse_args()
    # Arguments
    url =  args.url
    directory_bf = args.directory_bf
    urls_file = args.urls_file
    no_launch = args.no_cve_launch
    cms_scan = args.cms_scan
    nmap_file = args.nmap_file
    concurrent_targets = int(args.concurrent_targets)
    semaphore = asyncio.Semaphore(concurrent_targets)
    # L33t banner
    print_banner()
    # Sanitize the list of urls
    loop = asyncio.get_event_loop()
    urls = loop.run_until_complete(url_sanitize(urls_file, url, nmap_file))
    for url in urls:
        print(url)
    # Handling the dockers with care, if something crashes, we need to stop all of them
    try:
        # Start cve-search docker
        cve_search = cve_search_start(no_launch)
        print('[+] Starting checking')
        with ProcessPoolExecutor(max_workers=concurrent_targets) as executor:
            futures = []
            port = 5001
            for url in urls:
                futures.append(executor.submit(check_website, url, cms_scan, port))
                port += 1
            try:
                for future in as_completed(futures):
                    checks.append(future.result())
            except KeyboardInterrupt:
                for future in futures:
                    future.cancel()
                executor.shutdown(wait=False)
        # Waiting for threads to complete
        #print("[i] Waiting for threads to finish")
        #for thread in threads:
        #    if thread.isAlive():
        #        thread.join()
        # Output the results
        for check in checks:
            if check:
                print(check.to_string())
        # Write html report
        to_write = write_html(checks)
        open("report.html", "w").write(report.format(to_write))
        print("[+] Html report written to report.html")
    finally:
        if not no_launch:
            remove_container(cve_search)
        for docker in docker_ids:
            remove_container(docker)
