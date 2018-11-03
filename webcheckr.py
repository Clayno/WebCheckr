#!/usr/bin/python3
# coding: utf-8

import sys
import docker
import json
import requests
from time import sleep

images = {
        "Wappalyzer": "wappalyzer/cli",
        "Wpscan": "wpscanteam/wpscan",
        "Gobuster": "kodisha/gobuster",
        "Joomscan": "pgrund/joomscan",
        "Drupwn": "immunit/drupwn",
        "CVE-search": "ttimasdf/cve-search:withdb"
        }

commands = {
        "Wpscan": "--url {0} --no-banner",
        "Joomscan": "--url {0}",
        "Drupwn": "enum {0}"
        }

scanners = {
        "WordPress": "Wpscan",
        "Joomla": "Joomscan",
        "Drupal": "Drupwn"
        }

filename = ""

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
    print_and_report("[+] Checking the technologies running on the website")
    # Wappalizer recursive with Chrome user-agent
    try: 
        # Should maybe be with the other comands ?
        command = "{0} --recursive=1 --user-agent='Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.75 Safari/537.1'".format(url)
        client = docker.from_env()
        container = client.containers.run(images["Wappalyzer"], command, detach=True)
        response = ""
        for line in container.logs(stream=True):
            response += line.decode()
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
    print_and_report("[+] Launching {0}".format(scanner))
    try:
        client = docker.from_env()
        container = client.containers.run(images[scanner], commands[scanner].format(url), detach=True)
        for line in container.logs(stream=True):
            print_and_report(line.decode(), end="")
    finally:
        remove_container(container)

def gobuster(url):
    print("[-] Bruteforcing directories/files in background")
    try:
        # Directory bruteforce with force wildcards without checking certificate
        command = "-u {0} -w {1} -fw -k -q".format(url, "/data/wordlists/common.txt")
        client = docker.from_env()
        container = client.containers.run(images["Gobuster"], command, detach=True)
        return container
    finally:
        remove_container(container)

def cve_search():
    command = "" 
    client = docker.from_env()
    container = client.containers.run(images["CVE-search"], command,
            ports={5000: ('127.0.0.1', 5000)} ,detach=True)
    return container

def query_cve(name, version, container):
    print_and_report("[+] Searching cve for {0} ({1})".format(name, version))
    name = name.lower().replace(" ", ":")
    command = "search.py -p '{0}:{1}'".format(name, version)
    exit_code, output = container.exec_run(command)
    print_and_report(output.decode())
    
def remove_container(container):
    try: 
        statuses = ['removed', 'exited', 'dead']
        if container.status not in statuses:
            container.kill()
    except:
        pass

def print_and_report(string='\n'):
    print(string)
    if os.path.exists(filename):
        print(string, file=open(filename, 'a'))
    else:
        print(string, file=open(filename, 'w'))



if __name__ == "__main__":
    import argparse
    import os
    from urllib.parse import urlparse
    parser  = argparse.ArgumentParser(description="WebCheckr - Initial check for web pentests")
    parser.add_argument('-p', '--proxy',  action='store', help="HTTP proxy to use - not implemented")
    parser.add_argument('-d', '--directory_bf', action='store_true', help='Launch directory bruteforce with common.txt from Seclist')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-U', '--urls_file', action='store', help='Provide file instead of url, one per line')
    group.add_argument('-u', '--url', help="URL of target site")
    args = parser.parse_args()
    # Arguments
    url =  args.url
    proxy = args.proxy
    directory_bf = args.directory_bf
    urls_file = args.urls_file
    # L33t banner
    print_banner()
    # Check if there is a list of urls
    if urls_file is not None:
        urls = open(urls_file).readlines()
    else:
        urls=[url]
    try:
        print("[+] Starting the CVE-search docker, this may take some time...")
        # Count 5~10min to start
        cve_search = cve_search()
        response = ""
        while response != 200:
            sleep(10)
            try:
                response = requests.get("http://127.0.0.1:5000").status_code
            except:
                pass
        global filename
        # Start the scanning
        for url in urls:
            hostname = urlparse(url).hostname
            filename = hostname
            print_and_report("[+] Scanning {0}".format(url))
            # Starting bruteforce of directory in background
            if directory_bf:
                buster_container = gobuster(url)
            # Start analysing web application
            found = wappalyzer(url)
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
                if cms[0] in scanners.keys():
                    cms_scanner(url, scanners[cms[0]])
            # Printing the directory bruteforce. Shouldn't block processing if multiple urls...
            if directory_bf:
                print_and_report("[+] Getting back to bruteforcing results")
                for line in buster_container.logs(stream=True):
                    print_and_report(line.decode(), end="")
                print_and_report()
    finally:
        remove_container(cve_search)

    
