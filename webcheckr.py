#!/usr/bin/python3
# coding: utf-8

import sys
import os
import docker
import json
import requests
import threading
import argparse
import os
import base64
from urllib.parse import urlparse
from time import sleep
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

# Docker images installed and used
images = {
        "Wappalyzer": "wappalyzer/cli",
        "Wpscan": "wpscanteam/wpscan",
        "Gobuster": "kodisha/gobuster",
        "Joomscan": "pgrund/joomscan",
        "Drupwn": "immunit/drupwn",
        "CVE-search": "ttimasdf/cve-search:withdb",
        "Selenium": "selenium/standalone-chrome",
        "Changeme": "ztgrace/changeme"
        }

# Commands given to dockers
commands = {
        "Wpscan": "--url {0} --no-banner",
        "Joomscan": "--url {0}",
        "Drupwn": "enum {0}",
        "CVE-search": "{0}",
        "Wappalyzer": "{0}",
        "Wappalyzer_recursive": "{0} --recursive=1",
        "Gobuster": "-fw -w {0} -u {1} -k -q",
        "Selenium": "",
        "Changeme": "{0}"
        }

# CMS for which we have scanners
scanners = {
        "WordPress": "Wpscan",
        "Joomla": "Joomscan",
        "Drupal": "Drupwn"
        }

# Ouput directory (depends on current URL)
directory = ""

# List of dockers id
docker_ids = []

# List of threads
threads = []

# Template of report
report = '''<!DOCTYPE html>
<html>
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

# List of class check
checks = []

# Class containing data for a check
class Check:
    def __init__(self, hostname, directory, screen_path, 
            wappalyzer, cve):
        self.hostname = hostname
        self.directory = directory
        self.screen_path = screen_path
        self.wappalyzer = wappalyzer
        self.cve = cve


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


def cms_scanner(url, scanner):
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
            print_and_report(line.decode().strip(), "{0}.txt".format(scanner), url=url)
    finally:
        remove_container(container)

def gobuster(url, wordlist):
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
            print_and_report(line.decode().strip(), "gobuster.txt", url=url)
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
    response = ""
    while response != 200:
        try:
            response = requests.get("http://127.0.0.1:5000").status_code
        except:
            pass
        sleep(2)
    return container

def query_cve(name, version, container):
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
            print_and_report('CVE   : {0}'.format(vuln['id']), filename)
            print_and_report('DATE  : {0}'.format(vuln['Published']), filename)
            print_and_report('CVSS  : {0}'.format(vuln['cvss']), filename)
            print_and_report('{0}'.format(vuln['summary']), filename)
            print_and_report('\n', filename)
            print_and_report('References:\n-----------------------\n', filename)
            for url in vuln['references']:
                print_and_report(url, filename)
            print_and_report('\n', filename)
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

def print_and_report(string='', filename='', url=''):
    """
    Print to output and to file.

    Note:
        If filename is empty, writing to report.txt in the current 
        directory (URL of the target).

    Args:
        string (str): String to print
        filename (str): File to write to
        url (str): Url scanned to determine directory
    """
    if filename == '':
        print(string)
        filename = 'report.txt'
    if url == '':
        if not os.path.exists(directory):
                os.makedirs(directory)
        filename = "{0}/{1}".format(directory, filename)
    else:
        filename = "{0}/{1}".format(urlparse(url.strip()).hostname, filename)
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
                if host.get_service(port[0]).service == 'http':
                    if host.hostnames:
                        http_open.append("http://{0}:{1}".format(host.hostnames[0], port[0]))
                    else:
                        http_open.append("http://{0}:{1}".format(host.address, port[0]))
                elif host.get_service(port[0]).service == 'https':
                    if host.hostnames:
                        http_open.append("https://{0}:{1}".format(host.hostnames[0], port[0]))
                    else:
                        http_open.append("https://{0}:{1}".format(host.address, port[0]))
    return http_open
            

def url_sanitize(urls_file, url, nmap_file):
    """
    Organize all the urls input.
    Check if the list of urls have already been scanned.

    Args:
        urls_file (str): Paht to file containing the urls to scan
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
    for i in range(len(urls)):
        if 'http://' not in urls[i] and 'https://' not in urls[i]:
            urls[i] = 'http://{0}'.format(urls[i])
    for url in urls:
        if os.path.exists(urlparse(url.strip()).hostname):
            print("[-] Removing {0} (already scanned)".format(url))
            urls.remove(url)
    if len(urls) == 0:
        print("[x] No urls provided. Quitting...")
        exit()
    return urls

def selenium_start():
    try: 
        client = docker.from_env()
        container = client.containers.run(images["Selenium"], 
                commands["Selenium"].format(url),
                ports={4444: ('127.0.0.1', 5007)},
                detach=True, auto_remove=True)
        docker_ids.append(container)
        sleep(5)
        driver = webdriver.Remote("http://127.0.0.1:5007/wd/hub", 
                DesiredCapabilities.CHROME)
        driver.implicitly_wait(30)
        return driver
    except:
        remove_container(container)
        return None

def selenium_get(url):
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
        if not os.path.exists(directory):
            os.makedirs(directory)
            screen = driver.get_screenshot_as_png()
            screen_path = "{0}/{1}.png".format(directory, 
                    base64.b64encode(url.encode()).decode())
            open(screen_path, "wb").write(screen)
        return screen_path
    except Exception as e:
        print("[!] Couldn't take screenshot {0}".format(str(e)))


def analyze_found(found, cms_scan):
    '''
    Print and launch a cve-search for all the valid element in found.
    An element is valid if a version is determined alongside the technology.
    Also start the corresponding CMS scanner if one has been detected and the
    option is activated.

    Args:
        found (list): list of technologies found
        cms_scan (boolean): true start scan, false don't
    '''
    # Maybe not for all the tech, we don't care for css, jquery,...
    # https://www.wappalyzer.com/docs/categories
    for_return = []
    for category, l in found.items():
        print_and_report('|----{0}:'.format(category))
        for tech in l:
            name, version = tech.split(':', 1)
            if version == "":
                print_and_report('|        {0}'.format(name))
            else:
                vuln = query_cve(name, version, cve_search)
                if vuln != None:
                    print_and_report('|        {0} ({1}) \033[0;31m{2}\033[0m'.format(
                        name, version, vuln))
                    for_return.append((name,version,vuln))
                else:
                    print_and_report('|        {0} ({1})'.format(name, version))
    if "CMS" in found.keys():
        cms = [cms.split(':', 1)[0] for cms in found["CMS"]]
    else:
        cms = None
    # Check if a known CMS is detected
    if cms is not None:   
        print_and_report("\033[0;32m[+] {0} found !\033[0m".format(cms[0]))
        print_and_report()
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
        final += '''<div class="check">
    <div class="check-title">
        <h2>{0}</h2>
        <button onclick="togglediv('content{5}')">toggle</button>
    </div>
    <div class="content" id="content{5}">
        <p>
        <b>Directory:</b> {1}</br>
        </p>
        <img class="screenshot" src="{2}">
        <p class="techologies">
        <b>Technologies found:</b></br>
            {3}</br>
        </p>
        <p class="cve">
        <b>CVE found:</b></br>
            {4}</br>
        </p>
    </div>
</div>
</br>'''.format(check.hostname, check.directory, check.screen_path,
                check.wappalyzer, check.cve, str(i))
        i+=1
    return final
        

if __name__ == "__main__":
    parser  = argparse.ArgumentParser(description="WebCheckr - Initial check for web pentests")
    parser.add_argument('-d', '--directory_bf', action='store', help='Launch directory bruteforce with provided wordlist (full path)')
    parser.add_argument('-n', '--no_cve_launch', action='store_true', help='Do not launch cve-search docker, you have to start it manually: docker start cvesearch')
    parser.add_argument('-c', '--cms_scan', action='store_true', help='Launch CMS scanner if detected. Supported: Wordpress, Joomla, Drupal')
    parser.add_argument('-i', '--nmap_file', action='store', help='Provide XML nmap report with or instead of urls. This will launch the script to every http/https service found')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-U', '--urls_file', action='store', help='Provide file instead of url, one per line')
    group.add_argument('-u', '--url', help="URL of target site")
    args = parser.parse_args()
    # Arguments
    url =  args.url
    directory_bf = args.directory_bf
    urls_file = args.urls_file
    no_launch = args.no_cve_launch
    cms_scan = args.cms_scan
    nmap_file = args.nmap_file
    # L33t banner
    print_banner()
    # Sanitize the list of urls
    urls = url_sanitize(urls_file, url, nmap_file)
    # Handling the dockers with care, if something crashes, we need to stop all of them
    try:
        # Start cve-search docker
        cve_search = cve_search_start(no_launch)
        # Start Selenium docker
        driver = selenium_start()
        # Start the scanning
        for url in urls:
            # Getting hostname to create report file
            hostname = urlparse(url.strip()).hostname
            directory = "{0}/{1}".format(os.getcwd(), hostname)
            print("\033[94m[+] Scanning {0}\033[0m".format(url))
            # Get basic informations with selenium
            screen_path = selenium_get(url)
            if directory_bf is not None:
                # Starting bruteforce of directory in background
                thread = threading.Thread(target=gobuster, args=(url, directory_bf, ),)
                threads.append(thread)
                thread.start()
            # Start analysing web application
            print("[i] Checking the technologies running on the website")
            found = wappalyzer(url)
            if found == None or not found :
                print("[x] Couldn't get any technologies on this website")
                check = Check(hostname, directory, screen_path, found, None)
                checks.append(check)
                continue
            # Analyze the foundings by Wappalyzer and start CMS scan if asked
            vulns = analyze_found(found, cms_scan)
            check = Check(hostname, directory, screen_path, found, vulns)
            checks.append(check)
        # Waiting for threads to complete
        print("[i] Waiting for threads to finish")
        for thread in threads:
            if thread.isAlive():
                thread.join()
        # Write html report
        to_write = write_html(checks)
        open("report.html", "w").write(report.format(to_write))
        print("[+] Html report written to report.html")
    finally:
        if not no_launch:
            remove_container(cve_search)
        for docker in docker_ids:
            remove_container(docker)
