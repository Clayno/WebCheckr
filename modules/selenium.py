from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from helpers.dockers import remove_container, docker_wrapper
from modules.WebcheckrModule import WebcheckrModule
from time import sleep
import base64
import requests
import traceback

docker_image = "selenium/standalone-chrome"

def selenium_start():
    '''
    Starting Selenium Chrome docker.

    Returns:
        driver: Driver associated to the selenium container
        container: Docker container
    '''
    try:
        container = docker_wrapper(docker_image, 
                shm_size="128M")
        while 1:
            try:
                resp = requests.get('http://{name}:4444/wd/hub/status'
                        .format(name=container.name)).json()
                if resp['value']['ready'] == True:
                    break
            except:
                sleep(1)
                continue
        options = webdriver.ChromeOptions()
        options.headless = True
        options.add_argument('--disable-gpu')
        options.add_argument('--windows-size=1920,1080')
        driver = webdriver.Remote("http://{name}:4444/wd/hub".format(name=container.name), 
                DesiredCapabilities.CHROME, options=options)
        driver.implicitly_wait(30)
        return driver, container
    except Exception as e:
        if container:
            remove_container(container)
        return None

class SeleniumModule(WebcheckrModule):
    result = None

    def __init__(self, url, directory, driver, cprinter):
        super(SeleniumModule, self).__init__("selenium", url)
        self.directory = directory
        self.driver = driver
        self.cprinter = cprinter

    def _work(self):
        '''
        Get a screenshot and the title of the landing page.

        Args:
            url (str): Url to fetch

        Returns:
            path of the screenshot
        '''
        try:
            self.cprinter.logger.info('Starting selenium basic')
            self.driver.get(self.url)
            self.cprinter.found(string=f"Title: {self.driver.title}", url=self.url),
            screen = self.driver.get_screenshot_as_png()
            screen_path = "{0}/{1}.png".format(self.directory, 
                    base64.b64encode(self.url.encode()).decode())
            open(screen_path, "wb").write(screen)
            self.cprinter.logger.info('Screenshot written on disk')
            self.result = {"screenshot_path": screen_path,
                    "title": self.driver.title,
                    "screenshot": base64.b64encode(screen).decode()}
        except Exception as e:
            traceback.print_exc()
            self.state = 'error'
            self.cprinter.cprint(string="[!][{url}] Couldn't take screenshot".format(url=self.url),
                filename='',
                print_stdout=True)

    def _result(self):
        return self.result

