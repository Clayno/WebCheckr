#!/usr/bin/python3
# coding: utf-8

import sys
import os
import docker
import json
import requests
from time import sleep

# Docker images installed and used
images = {
        "Wappalyzer": "wappalyzer/cli",
        "Wpscan": "wpscanteam/wpscan",
        "Gobuster": "kodisha/gobuster",
        "Joomscan": "pgrund/joomscan",
        "Drupwn": "immunit/drupwn",
        "CVE-search": "ttimasdf/cve-search:withdb"
        }

# Commands given to dockers
commands = {
        "Wpscan": "--url {0} --no-banner",
        "Joomscan": "--url {0}",
        "Drupwn": "enum {0}",
        "CVE-search": "{0}",
        "Wappalyzer": "{0}",
        "Wappalyzer_recursive": "{0} --recursive=1"
        }

# CMS for which we have scanners
scanners = {
        "WordPress": "Wpscan",
        "Joomla": "Joomscan",
        "Drupal": "Drupwn"
        }

# Ouput directory (depends on current URL)
directory = ""

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
        Dict of found CMS otherwise
    """
    print_and_report("[+] Checking the technologies running on the website")
    try: 
        client = docker.from_env()
        container = client.containers.run(images["Wappalyzer"], 
                commands["Wappalyzer_recursive"].format(url),
                detach=True, auto_remove=True)
        response = ""
        for line in container.logs(stream=True):
            response += line.decode()
        # Sometimes, Wappalyzer doesn't work in recursive mode :'(
        if response == None or response == "":
            response = ""
            container = client.containers.run(images["Wappalyzer"], 
                commands["Wappalyzer"].format(url),
                detach=True, auto_remove=True)
            response = ""
            for line in container.logs(stream=True):
                response += line.decode()
            if response == None or response == "":
                return None
        # Now we have to parse the JSON response
        response = json.loads(response)
        applications = response['applications']
        found = {}
        for cell in applications:
            key = ''.join(v for v in cell['categories'][0].values())
            data = '{0}:{1}'.format(cell['name'], cell['version'])
            if key in found:
                found[key].append(data)
            else:
                found[key] = [data]
        for key, value in sorted(found.items()):
            # Printing as they appear in cli Wappalyzer output
            print_and_report('{0}:'.format(key))
            for val in value:
                name, version = val.split(':', 1)
                if version == "":
                    print_and_report('    {0}'.format(name))
                else:
                    print_and_report('    {0} ({1})'.format(name, version))
            print_and_report()
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
        for line in container.logs(stream=True):
            print_and_report(line.decode())
    finally:
        remove_container(container)

def gobuster(url):
    """
    Launch Gobuster docker.

    Args:
        url (str): URL to bruteforce

    Returns:
        container: launched gobuster container
        generator: streamed output of the docker
    """
    print("[-] Bruteforcing directories/files in background")
    try:
        # Directory bruteforce with force wildcards without checking certificate
        command = "-w {0} -u {1} -k -q".format("/wordlists/common.txt", url)
        client = docker.from_env()
        # Change this. Have to be an argument
        container = client.containers.run(images["Gobuster"], command, detach=True,
                volumes={'/home/layno/wordlist/': {'bind': '/wordlists', 'mode': 'ro'}},
                auto_remove=True)
        generator = container.logs(stream=True)
        return container, generator
    except:
        remove_container(container)

def cve_search():
    """
    Starts the CVE-search docker.
    """
    command = "" 
    client = docker.from_env()
    container = client.containers.get('cvesearch')
    container.start()
    #container = client.containers.run(images["CVE-search"], command,
    #        ports={5000: ('127.0.0.1', 5000)} ,detach=True)
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
    print_and_report("[i] Searching cve for {0} ({1})".format(name, version))
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
            print_and_report('|     {0} vulnerabilities and {1} with a cvss > 7.5'
                    .format(vulns['total'], vulns['critical']))

    
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

def print_and_report(string='', filename=''):
    """
    Print to output and to file.

    Note:
        If filename is empty, writing to report.txt in the current 
        directory (URL of the target).

    Args:
        string (str): String to print
        filename (str): File to write to
    """
    if filename == '':
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
                if host.get_service(port[0]).service == 'http':
                    http_open.append("http://{0}:{1}".format(host.hostnames[0], port[0]))
                elif host.get_service(port[0]).service == 'https':
                    http_open.append("https://{0}:{1}".format(host.hostnames[0], port[0]))
    return http_open
            

if __name__ == "__main__":
    import argparse
    import os
    from urllib.parse import urlparse
    parser  = argparse.ArgumentParser(description="WebCheckr - Initial check for web pentests")
    parser.add_argument('-p', '--proxy',  action='store', help="HTTP proxy to use - not implemented")
    parser.add_argument('-d', '--directory_bf', action='store_true', help='Launch directory bruteforce with common.txt from Seclist')
    parser.add_argument('-n', '--no_cve_launch', action='store_true', help='Do not launch cve-search docker, you have to start it manually: docker start cvesearch')
    parser.add_argument('-c', '--cms_scan', action='store_true', help='Launch CMS scanner if detected. Supported: Wordpress, Joomla, Drupal')
    parser.add_argument('-i', '--nmap_file', action='store', help='Provide XML nmap report instead of urls. This will launch the script to every http/https service found')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-U', '--urls_file', action='store', help='Provide file instead of url, one per line')
    group.add_argument('-u', '--url', help="URL of target site")
    args = parser.parse_args()
    # Arguments
    url =  args.url
    proxy = args.proxy
    directory_bf = args.directory_bf
    urls_file = args.urls_file
    no_launch = args.no_cve_launch
    cms_scan = args.cms_scan
    nmap_file = args.nmap_file
    # L33t banner
    print_banner()
    # Check if there is a list of urls
    urls = []
    if urls_file is not None:
        urls = open(urls_file).readlines()
    elif url is not None:
        urls=[url]
    if nmap_file is not None:
        urls.extend(nmap_retrieve(nmap_file))
    if len(urls) == 0:
        print("[x] No urls provided. Quitting...")
        exit()
    for i in range(len(urls)):
        if 'http://' not in urls[i] and 'https://' not in urls[i]:
            urls[i] = 'http://{0}'.format(urls[i])
    try:
        if no_launch:
            cve_search = docker.from_env().containers.get('cvesearch')
        else:
            print("[+] Starting the CVE-search docker, this may take some time...")
            # Count 5~10min to start
            cve_search = cve_search()
        print("[+] Checking if container is up...")
        response = ""
        while response != 200:
            try:
                response = requests.get("http://127.0.0.1:5000").status_code
            except:
                pass
            sleep(10)

        # Start the scanning
        for url in urls:
            # Getting hostname to create report file
            hostname = urlparse(url.strip()).hostname
            directory = hostname
            print_and_report("[+] Scanning {0}".format(url), )
            if directory_bf:
                # Starting bruteforce of directory in background
                buster_container, buster_generator = gobuster(url)
            # Start analysing web application
            found = wappalyzer(url)
            if found == None:
                print_and_report("[x] Couldn't get any technologies on this website")
                continue
            # Maybe not for all the tech, we don't care for css, jquery,...
            # https://www.wappalyzer.com/docs/categories
            for category, l in found.items():
                for tech in l:
                    name, version = tech.split(':', 1)
                    if version != "":
                        query_cve(name, version, cve_search)
            if "CMS" in found.keys():
                cms = [cms.split(':', 1)[0] for cms in found["CMS"]]
            else:
                cms = None
            # Check if a known CMS is detected
            if cms is not None:   
                print_and_report("[+] {0} found !".format(cms[0]))
                print_and_report()
                if cms_scan == True:
                    if cms[0] in scanners.keys():
                        cms_scanner(url, scanners[cms[0]])
            # Printing the directory bruteforce. Shouldn't block processing if multiple urls...
            if directory_bf:
                print_and_report("[i] Getting back to bruteforcing results")
                for line in buster_generator:
                    print_and_report(line.decode())
                print_and_report()
    finally:
        if not no_launch:
            remove_container(cve_search)
        if directory_bf:
            if buster_container != None:
                remove_container(buster_container)

