import asyncio
import aiohttp
import logging
from urllib.parse import urlparse

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
            

async def validate_url(session, url, timeout):
    '''
    Returns url if connectivity went right. With priority on https scheme.
    '''
    logger = logging.getLogger('webcheckr')
    responses = await asyncio.gather(session.get(url[0], verify_ssl=False, timeout=timeout), 
            session.get(url[1], verify_ssl=False, timeout=timeout), return_exceptions=True)
    logger.debug(f'Result of {url[0]}: {responses}')
    # Check status of response to determine if service is up or not
    if hasattr(responses[1], 'status') and responses[1].status != None:
        return url[1]
    elif hasattr(responses[0], 'status') and responses[0].status != None:
        return url[0]
    return None


async def url_sanitize(urls_file, url, nmap_file, timeout):
    """
    Organize all the urls input.
    Check if the list of urls have already been scanned.

    Args:
        urls_file (str): Path to file containing the urls to scan
        url (str): Single url to scan
        nmap_file (str): Path to nmap scan to retrieve urls to scan from
    """
    logger = logging.getLogger('webcheckr')
    urls = []
    if urls_file is not None:
        urls = open(urls_file).readlines()
    elif url is not None:
        urls=[url]
    if nmap_file is not None:
        urls.extend(nmap_retrieve(nmap_file))
    urls = [url.strip() for url in urls]
    urls = set(urls)
    # Test the urls for connectivity
    to_test = []
    tmp_urls = set()
    async with aiohttp.ClientSession() as session:
        for url in urls:
            if '://' not in url: 
                hostname = urlparse('http://'+url).hostname
                tmp_urls.add(('http://{0}'.format(url), 
                    'https://{0}'.format(url)))
            else:
                parsed = urlparse(url)
                tmp_urls.add((f'http://{parsed.netloc}{parsed.path}', 
                    f'https://{parsed.netloc}{parsed.path}'))
        for urls in tmp_urls:
            to_test.append(validate_url(session, urls, timeout))
        results = await asyncio.gather(*to_test)   
    
    final = []
    to_test = list(to_test)
    tmp_urls = list(tmp_urls)
    for i in range(len(tmp_urls)):
        if not results[i]:
            print("[x] Impossible to reach {0}. Removing it...".format(urlparse(tmp_urls[i][0]).netloc))
        else:
            final.append(results[i])
    final = list(set(final))
    if len(final) == 0:
        print("[x] No urls provided. Quitting...")
        exit()
    return final


