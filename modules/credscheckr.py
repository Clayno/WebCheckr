from modules.WebcheckrModule import WebcheckrModule
from modules.CredsCheckr.credscheckr import *

class CredsCheckrModule(WebcheckrModule):
    result = None

    def __init__(self, url, credentials_filename, host, port, cprinter, test_creds=True):
        super(CredsCheckrModule, self).__init__('credscheckr', url)
        self.credentials_filename = credentials_filename
        self.host = host
        self.port = port
        self.test_creds = test_creds
        self.cprinter = cprinter

    def _work(self):
        try:
            credentials = get_credentials(self.credentials_filename)
            driver = get_new_selenium_driver(self.host, self.port)
            answer = is_login_page(driver, self.url)
            self.cprinter.logger.debug(answer)
            result = None
            if answer['scheme'] == 'form':
                self.cprinter.found('Form login page detected', url=self.url)
                if self.test_creds:
                    result = test_creds_form(answer['url'], credentials, self.host, self.port)
            elif answer['scheme'] == 'basic_auth':
                self.cprinter.found('Basic auth protected page detected', url=self.url)
                if self.test_creds:
                    result = test_creds_basic_auth(answer['url'], credentials)
            if result:
                creds = ""
                for cred in result:
                    creds += f'{cred["username"]}:{cred["password"]}, '
                creds = creds[:-2]
                self.cprinter.highlight(f'Creds have been found: {creds}', url=self.url)
            driver.close()
            answer['creds'] = result
            self.result = answer
            self.cprinter.logger.info(f'[{self.url}] credscheckr terminated')
        except Exception as e:
            self.cprinter.logger.exception('')
            traceback.print_exc()

    def _result(self):
        return self.result
    
    def to_html(self):
        final = '<p class="techologies">'
        final += "<b>CredsCheckr</b></br>"
        if self.result['scheme'] == 'basic_auth':
            final += "Basic auth protected page</br>"
        elif self.result['scheme'] == 'form':
            final += "Form login page</br>"
        else:
            final += "Not an authentication page</br>"
        if self.result['creds'] is not None:
            final += "Creds found: "
            final += "<table>\n"
            final += '<th>Username</th><th>Password</th>\n'
            for cred in self.result['creds']:
                final += f'<tr><td>{cred["username"]}</td><td>{cred["password"]}</td></tr>\n'
            final += "</table>\n"
        final += '</p>'
        return final
