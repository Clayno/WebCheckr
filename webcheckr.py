#!/usr/bin/python3
# coding: utf-8

import sys
import docker
import json

images = {
        "Wappalyzer": "wappalyzer/cli",
        "Wpscan": "wpscanteam/wpscan",
        "Gobuster": "kodisha/gobuster",
        "Joomscan": "pgrund/joomscan",
        "Drupwn": "immunit/drupwn"
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
    print("[+] Checking the technologies running on the website")
    # Wappalizer recursive with Chrome user-agent
    command = "{0} --recursive=1 --user-agent='Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.75 Safari/537.1'".format(url)
    client = docker.from_env()
    response = json.loads(client.containers.run(images["Wappalyzer"], command, True).decode())
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
        print('{0}:'.format(key))
        for val in value:
            name, version = val.split(':', 1)
            if version == "":
                print('    {0}'.format(name))
            else:
                print('    {0} ({1})'.format(name, version))
        print()
    print(response["meta"])
    # return the modules found on the url
    return [cms.split(':', 1)[0] for cms in found["CMS"]]

def cms_scanner(url, scanner):
    print("[+] Launching {0}".format(scanner))
    client = docker.from_env()
    container = client.containers.run(images[scanner], commands[scanner].format(url), detach=True)
    for line in container.logs(stream=True):
        print(line.decode(), end="")

def gobuster(url):
    print("[-] Bruteforcing directories/files in background")
    # Directory bruteforce with force wildcards without checking certificate
    command = "-u {0} -w {1} -fw -k -q".format(url, "/data/wordlists/common.txt")
    client = docker.from_env()
    container = client.containers.run(images["Gobuster"], command, detach=True)
    return container

if __name__ == "__main__":
    import argparse
    parser  = argparse.ArgumentParser(description="WebCheckr - Initial check for web pentests")
    parser.add_argument('-p', '--proxy',  action='store', help="HTTP proxy to use - not implemented")
    parser.add_argument('-r', '--report',  action='store', help="Generate report to specified file - not implemented")
    parser.add_argument('-d', '--directory_bf', action='store_true', help='Launch directory bruteforce with common.txt from Seclist')
    parser.add_argument('-s', '--stealth', action='store_true', help='Be stealthy - not implemented')
    parser.add_argument('url', help="URL of target site")
    args = parser.parse_args()
    # Arguments
    url =  args.url
    proxy = args.proxy
    file_report = args.report
    directory_bf = args.directory_bf

    print_banner()
    # Starting bruteforce of directory in background
    if directory_bf:
        buster_container = gobuster(url)
    # Start analysing web application
    cms = wappalyzer(url)
    # Check if a known CMS is detected
    if cms is not None:    
        print("[+] {0} found !".format(cms[0]))
        cms_scanner(url, scanners[cms[0]])
        
    if directory_bf:
        print("[+] Getting back to bruteforcing results")
        for line in buster_container.logs(stream=True):
            print(line.decode(), end="")
    
