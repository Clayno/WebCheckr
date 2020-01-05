#!/usr/bin/python3
import os
from termcolor import colored
from urllib.parse import urlparse

class Cprinter:
    def __init__(self, base_dir, pbar, counter, logger):
        self.base_dir = base_dir
        self.pbar = pbar
        self.counter = counter
        self.logger = logger

    def cprint(self, string='', filename='report.txt', url='', print_stdout=False):
        """
        Print to output and to file.

        Note:
            If filename is not empty, write to filename in the specified
            directory.

        Args:
            string (str): String to print
            filename (str): File to write to
            directory (str): Directory to write to
        """
        if print_stdout:
            if self.pbar:
                with self.pbar.get_lock():
                    self.pbar.n = self.counter.value
                    self.pbar.write(string)
            else:
                print(string)
        if filename != '':
            filename = self._get_path(url, filename)
            if os.path.exists(filename):
                print(string, file=open(filename, 'a'))
            else:
                print(string, file=open(filename, 'w'))
    
    def info(self, string, url, filename='report.txt', attrs=[]):
        message = colored(f'[i][{url}] {string}', 'blue', attrs=[])
        self.cprint(string=message, url=url, filename=filename, print_stdout=True) 

    def found(self, string, url, filename='', attrs=[]):
        message = colored(f'[+][{url}] {string}', 'green', attrs=attrs)
        self.cprint(string=message, url=url, filename=filename, print_stdout=True)

    def highlight(self, string, url, filename='', attrs=['bold']):
        message = colored(f'[+][{url}] {string}', 'yellow', attrs=attrs)
        self.cprint(string=message, url=url, filename=filename, print_stdout=True)

    def increment_bar(self):
        self.pbar.update()
        self.counter.value += 1

    def _get_path(self, url, filename):
        parsed = urlparse(url)
        directory = f'{self.base_dir}/{parsed.netloc}'
        if not os.path.exists(directory):
            os.makedirs(directory)
        filename = "{0}/{1}".format(directory, filename)
        return filename 

