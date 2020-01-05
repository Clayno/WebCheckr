import docker
import requests
import json
from time import sleep

docker_image = "ttimasdf/cve-search:withdb"
docker_command = "{0}"

def cve_search_start(launch_cve_docker):
    """
    Starts the CVE-search docker.

    Args:
        launch_cve_docker (boolean): true start a docker, false get the one running

    Returns:
        Container of cvesearch docker
    """
    if not launch_cve_docker:
            container = docker.from_env().containers.get('cvesearch_docker')
    else:
        print("[i] Starting the CVE-search docker, this may take some time...")
        # Count 5~10min to start
        command = "" 
        client = docker.from_env()
        container = client.containers.get('cvesearch_docker')
        container.start()
        #container = client.containers.run(images["CVE-search"], command,
        #        ports={5000: ('127.0.0.1', 5000)} ,detach=True)
    print("[i] Checking if container is up...")
    while True:
        try:
            response = requests.get("http://{name}:5000".format(name=container.name)).status_code
            if response == 200:
                break
        except:
            pass
        sleep(2)
    return container

def query_cve(name, version, container, directory, cprinter):
    """
    Runs a search in the CVE-search container.

    Args:
        name (str): Name of the technology to analyse
        version (str): Version of the technology to analyse
        container: CVE-search container
    """
    filename = f'cve_search_{name}_{version}.txt'
    name = name.lower().replace(" ", ":")
    command = f"search.py -p '{name}:{version}' -o json"
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
            cprinter.cprint('CVE   : {0}'.format(vuln['id']), filename, url=url) 
            cprinter.cprint('DATE  : {0}'.format(vuln['Published']), filename, url=url) 
            cprinter.cprint('CVSS  : {0}'.format(vuln['cvss']), filename, url=url) 
            cprinter.cprint('{0}'.format(vuln['summary']), filename, url=url)
            cprinter.cprint('\n', filename, url=url)
            cprinter.cprint('References:\n-----------------------\n', filename, url=url)
            for url in vuln['references']:
                cprinter.cprint(url, filename, url=url) 
            cprinter.cprint('\n', filename, url=url) 
            vulns['total'] += 1
            if float(vuln['cvss']) > 7.5:
                vulns['critical'] += 1
        if vulns['total'] != 0:
            return {'name': name,
                    'version': version,
                    'number_cve': vulns['total'],
                    'number_critical_cve': vulns['critical']
                    }
        return None

