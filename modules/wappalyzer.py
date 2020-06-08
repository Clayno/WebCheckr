#!/usr/bin/python3
from helpers.dockers import docker_wrapper, remove_container
from modules.WebcheckrModule import WebcheckrModule
import json
import traceback

class WappalyzerModule(WebcheckrModule):
    response = None
    result = None
    docker_image = "wappalyzer/cli"
    docker_command = "{0}"
    docker_command_recursive = "{0} --recursive=1"
    
    def __init__(self, url, logger):
        super(WappalyzerModule, self).__init__("wappalyzer", url)
        self.logger = logger

    def _parse_output(self):
        applications = self.response['applications']
        # Converting json into dict => found
        found = {}
        for cell in applications:
            for key in cell['categories'].values():
                data = '{0}:{1}'.format(cell['name'], cell['version'])
                if key in found:
                    found[key].append(data)
                else:
                    found[key] = [data]
        if len(found) != 0:
            self.result = found
        return found

    def _work(self):
        """
        Launch Wappalyzer docker for the specified URL.

        Args:
            url (str): URL to analyse

        Returns:
            None if Wappalyzer doesn't work
            Dict of found technologies otherwise
        """ 
        try: 
            container = docker_wrapper(self.docker_image, 
                    self.docker_command_recursive.format(self.url))
            response = ""
            for line in container.logs(stream=True):
                if line.startswith(b'{'):
                    response += line.decode()
            # Sometimes, Wappalyzer doesn't work in recursive mode :'(
            try:
                response = json.loads(response)
            except:
                container = docker_wrapper(self.docker_image, 
                    self.docker_command.format(self.url))
                response = ""
                for line in container.logs(stream=True):
                    if line.startswith(b'{'):
                        response += line.decode()
                # Now we have to parse the JSON response
                try:
                    response = json.loads(response)
                except:
                    # If we can't parse it, means nothing was found !
                    response = None
            self.response = response
            self._parse_output()
        except: 
            traceback.print_exc()
        finally:
            if container:
                remove_container(container)

    def _result(self):
        return self.result

    def to_html(self):
        final = '<p class="techologies">'
        final += "<b>Technologies found</b></br>"
        if not self.result:
            final += "Nothing found"
        else:
            final += "<table>\n"
            for category, l in self.result.items():
                final += '<tr><td>{cat}</td><td>'.format(cat=category)
                for tech in l:
                    name, version = tech.split(':', 1)
                    if version=="" or not version or version=="None":
                        final += '{0}</br>'.format(name)
                    else:
                        final += '{0} ({1})</br>'.format(name, version)
                final += '</td>\n'
            final += "</table>\n"
        final += "</p>"
        return final

