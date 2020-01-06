#!/usr/bin/python3
from helpers.dockers import docker_wrapper, remove_container
from modules.WebcheckrModule import WebcheckrModule
import json
import traceback
import os

class DirsearchModule(WebcheckrModule):
    response = None
    result = None
    docker_image = "clayno/dirsearch"
    docker_command = "-E -u {0} --json-report=/tmp/output/dirsearch.json"
    
    def __init__(self, url, directory, cprinter):
        super(DirsearchModule, self).__init__("dirsearch", url)
        self.directory = directory
        self.cprinter = cprinter

    def _work(self):    
        """
        Launch Gobuster docker.

        Args:
            url (str): URL to bruteforce
        """
        try:
            container = docker_wrapper(self.docker_image, 
                    self.docker_command.format(self.url), 
                    volumes={"/tmp/webcheckr/output": {'bind': '/tmp/output', 'mode': 'rw'}})
            response = ""
            container.wait()
            with open('/tmp/webcheckr/output/dirsearch.json') as f:
                response = f.read()
            try:
                response = json.loads(response)
                for k,v in response.items():
                    self.result = v
            except:
                self.result = None
        except: 
            traceback.print_exc()
        finally:
            if container:
                remove_container(container)

    def _result(self):
        return self.result

    def to_html(self):
        final = '<p class="dirsearch">'
        final += "<b>Directories/Files found</b></br>"
        if not self.result:
            final += "Nothing found"
        else:
            final += "<table>\n"
            for found in self.result:
                final += f"<tr><td>{found['path']}</td><td>{found['status']}</td></tr>"
            final += "</table>\n"
        final += "</p>"
        return final

