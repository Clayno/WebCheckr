#!/usr/bin/python3
# coding: utf-8

import docker
import json
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import argparse
import base64
from time import sleep
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from cdifflib import CSequenceMatcher
from collections import defaultdict
import asyncio
import aiohttp
import traceback
import multiprocessing
import logging
from multiprocessing.pool import ThreadPool
try:
    import helpers.cprint
except:
    pass
docker_ids = []

logger = logging.getLogger(__name__)

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

def selenium_start():
    """
    Starts Selenium Docker and driver

    Returns:
        driver: Selenium Webdriver
    """
    try:
        client = docker.from_env()
        container = client.containers.run("selenium/standalone-chrome",
                "",
                ports={4444: ('127.0.0.1', 5007)},
                shm_size="128M", # https://github.com/elgalu/docker-selenium/issues/20
                detach=True, auto_remove=True)
        docker_ids.append(container)
        while 1:
            try:
                resp = requests.get('http://127.0.0.1:5007/wd/hub/status').json()
                if resp['value']['ready'] == True:
                    break
            except:
                sleep(1)
                continue
        options = webdriver.ChromeOptions()
        options.headless = True
        driver = webdriver.Remote("http://127.0.0.1:5007/wd/hub",
                DesiredCapabilities.CHROME, options=options)
        driver.implicitly_wait(10)
        return driver
    except Exception as e:
        remove_container(container)
        return None

def get_new_selenium_driver(host, port):
    """
    Starts new Selenium Webdriver

    Returns:
        driver: Selenium Webdriver
    """
    options = webdriver.ChromeOptions()
    options.headless = True
    driver = webdriver.Remote(f"http://{host}:{port}/wd/hub",
            DesiredCapabilities.CHROME, options=options)
    driver.implicitly_wait(10)
    return driver


def form_score(form):
    """
    Calculate score of a form. This score should determine if this is a login form or not.
    Below 20, there is a chance that it's not the case

    Args:
        form: Form to analyze

    Returns
        score: Form score
    """
    score = 0
    inputs = form.find_elements_by_xpath('//input')
    # In case of user/pass or user/pass/remember-me
    if len(inputs) in (2, 3):
        score += 10
    typecount = defaultdict(int)
    for x in inputs:
        type_ = x.get_property('type') if isinstance(x, webdriver.remote.webelement.WebElement) else "other"
        typecount[type_] += 1
    logger.debug(f'{typecount}')
    if typecount['text'] in [1, 2]:
        score += 10
    if not typecount['text']:
        score -= 10
    if typecount['password'] == 1:
        score += 10
    if not typecount['password']:
        score -= 10
    if typecount['checkbox'] > 1:
        score -= 10
    if typecount['radio']:
        score -= 10
    return score


def pick_form(driver):
    """Return the form most likely to be a login form"""
    forms = driver.find_elements_by_xpath('//form')
    return sorted(forms, key=form_score, reverse=True)[0]


def pick_fields(form):
    """Return the most likely field names for username and password"""
    userfield = passfield = emailfield = buttonfield = None
    inputs = form.find_elements_by_xpath('//input')
    buttons = form.find_elements_by_xpath('//button')
    if buttons:
        buttonfield = buttons[0]
    for x in inputs:
        if not isinstance(x, webdriver.remote.webelement.WebElement):
            continue
        type_ = x.get_attribute('type')
        if type_ == 'password' and passfield is None:
            passfield = x
        elif type_ == 'email' and emailfield is None:
            emailfield = x
        elif type_ == 'text' and userfield is None:
            userfield = x
        elif type_ == 'submit' and buttonfield is None:
            buttonfield = x
    return emailfield or userfield, passfield, buttonfield

def page_score(driver):
    """
    Calculate score of the driver current page in terms of likelihood to be a login page

    Returns:
        max_score: best score of all forms
        best_form: Best form in terms of score
    """
    forms = driver.find_elements_by_xpath('//form')
    inputs = driver.find_elements_by_xpath('//input')
    form_scores = {}
    max_score = 0
    best_form = None
    for form in forms:
        score = form_score(form)
        form_scores[form] = score
        if score > max_score:
            max_score = score
            best_form = form
    return max_score, best_form

def get_form_objects(driver):
    return pick_fields(pick_form(driver))


def is_login_page(driver, url):
    answer = {'url': url,
            'scheme': None}
    response = requests.get(url, verify=False)
    if 'www-authenticate' in response.headers.keys():
        if response.headers['www-authenticate'].startswith("Basic "):
            answer['scheme'] = 'basic_auth'
            return answer
    driver.get(url)
    source = driver.page_source
    score, form = page_score(driver)
    logger.debug(f"[i] Score: {score}")
    if score >= 20:
        answer['scheme'] = 'form'
        username_input, password_input, click_button = pick_fields(form)
        answer['objects'] = {
                'username_input': username_input,
                'password_input': password_input,
                'click_button': click_button
                }
    return answer

async def async_test_cred(url, username, password, semaphore, success):
    try:
        async with aiohttp.ClientSession() as session:
            async with semaphore:
                response = await session.get(url, ssl=False,
                        auth=aiohttp.BasicAuth(username, password))
                if response.status not in [401, 500]:
                    success.set()
                    return {'return_code': response.status,
                            'username': username,
                            'password': password}
                else:
                    return None
    except asyncio.CancelledError:
        if session:
            await session.close()

async def cleaner(success, tasks):
    await success.wait()
    for task in tasks:
        task.cancel()

async def gather_tasks(tasks):
    return await asyncio.gather(*tasks, return_exceptions=True)

def test_creds_basic_auth(url, credentials, validation_test=None):
    try:
        # There are no loop in Thread, need to try
        try:
            loop = asyncio.get_event_loop()
            assert loop != None
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        semaphore = asyncio.Semaphore(10)
        tasks = []
        success = asyncio.Event()
        for credential in credentials:
            username = credential['username']
            password = credential['password']
            tasks.append(loop.create_task(async_test_cred(url, username, password, semaphore, success)))
        waiter_worker = loop.create_task(cleaner(success, tasks))
        results = loop.run_until_complete(gather_tasks(tasks))
        logger.debug(f'results: {results}')
        to_return = [ obj for obj in results if obj is not None ]
        success.set()
        return to_return
    except:
        traceback.print_exc()

def take_screenshot(driver):
    screen = driver.get_screenshot_as_png()
    screen_path = "{0}.png".format(base64.b64encode("{0}:{1}".format(username,password).encode()).decode())
    open(screen_path, "wb").write(screen)

def finished_form_test(result):
    if result is not None:
        pool.terminate()

def test_cred_form(url, username, password, host, port):
    try:
        driver = get_new_selenium_driver(host, port)
        driver.get(url)
        initial_page = driver.page_source
        username_input, password_input, click_button = get_form_objects(driver)
        username_input.clear()
        username_input.send_keys(username)
        password_input.clear()
        password_input.send_keys(password)
        click_button.click()
        sleep(3)
        m = CSequenceMatcher(None, initial_page, driver.page_source)
        logger.debug(f"{username}:{password} ratio: {m.ratio()}")
        if m.ratio() < 0.8:
            return [{'ratio': m.ratio(),
                    'username': username,
                    'password': password
                    }]
        return None
    except Exception as e:
        logger.error(e)
    finally:
        if driver is not None:
            driver.close()


def test_creds_form(url, credentials, host, port):
    '''
    Test a credential on an authentication page.

    Args:
        todo

    Returns:
        todo
    '''
    class Executor:
        def __init__(self, thread_num):
            self.results = None
            self.pool = ThreadPool(thread_num)

        def finished_form_test(self, result):
            if result is not None:
                self.results = result
                self.pool.terminate()

        def schedule(self, function, args):
            self.pool.apply_async(function, args=args, callback=self.finished_form_test)

        def wait(self):
            self.pool.close()
            self.pool.join()

        def terminate(self):
            self.pool.terminate()
    try:
        executor = Executor(5)
        for credential in credentials:
            username = credential['username']
            password = credential['password']
            executor.schedule(test_cred_form,
                    args=(url, username, password, host, port, ))
        executor.wait()
        result = None
        if executor.results is not None:
            result = [res for res in executor.results if res is not None]
        return result
    except:
        if executor is not None:
            executor.terminate()
        traceback.print_exc()

def analyze_url(url, credentials_file, host, port):
    try:
        with open(credentials_file, 'r') as f:
            creds = f.readlines()
        credentials = []
        for cred in creds:
            username, password = cred.strip("\n").split(':')
            credentials.append({"username": username, "password": password})
        driver = get_new_selenium_driver(host, port)
        answer = is_login_page(driver, url)
        logger.debug(answer)
        if answer['scheme'] == 'form':
            print(f'[+] [{url}] Form login page detected')
            result = test_creds_form(answer['url'], credentials, host, port)
        elif answer['scheme'] == 'basic_auth':
            print(f'[+] [{url}] Basic auth protected page detected')
            result = test_creds_basic_auth(answer['url'], credentials)
        else:
            return None
        logger.debug(result)
        if result:
            creds = ""
            for cred in result:
                creds += f'{cred["username"]}:{cred["password"]}, '
            creds = creds[:-2]
            print(f'[+] [{url}] Creds have been found: {creds}')
        driver.close()
    except:
        traceback.print_exc()

def get_credentials(credentials_filename):
    with open(credentials_filename, 'r') as f:
        creds = f.readlines()
        credentials = []
        for cred in creds:
            username, password = cred.strip("\n").split(':')
            credentials.append({"username": username, "password": password})
    return credentials

class CredsCheckrModule:
    name = "credscheckr"
    result = None
    state = None

    def __init__(self, cprinter):
        self.cprinter = cprinter

    def run(self, url, credentials_filename, host, port, test_creds=True):
        try:
            self.state = 'started'
            credentials = get_credentials(credentials_filename)
            driver = get_new_selenium_driver(host, port)
            answer = is_login_page(driver, url)
            self.cprinter.logger.debug(answer)
            result = None
            if answer['scheme'] == 'form':
                self.cprinter.found('Form login page detected', url=url)
                if test_creds:
                    result = test_creds_form(answer['url'], credentials, host, port)
            elif answer['scheme'] == 'basic_auth':
                self.cprinter.found('Basic auth protected page detected', url=url)
                if test_creds:
                    result = test_creds_basic_auth(answer['url'], credentials)
            if result:
                creds = ""
                for cred in result:
                    creds += f'{cred["username"]}:{cred["password"]}, '
                creds = creds[:-2]
                self.cprinter.highlight(f'Creds have been found: {creds}', url=url)
            driver.close()
            answer['creds'] = result
            self.result = answer
            self.state = 'terminated'
            self.cprinter.logger.info('credscheckr terminated')
            return {self.name: self.result}
        except Exception as e:
            self.state = 'error'
            self.cprinter.logger.error(f'error in credscheckr {e}')
            traceback.print_exc()

    def to_html(self):
        try:
            final = ""
            final += f"<b>{self.name}</b></br>"
            if self.result['scheme'] == 'basic_auth':
                final += "Basic auth protected page"
            elif self.result['scheme'] == 'form':
                final += "Form login page</br>"
            else:
                final += "Not an authentication page</br>"
            if self.result['creds'] is not None:
                final += "Creds found: "
                final = "<table>\n"
                final += '<th>Username</th><th>Password</th>\n'
                for cred in self.result['creds']: 
                    final += f'<tr><td>{cred["username"]}</td><td>{cred["password"]}</td></tr>\n'
                final += "</table>\n"
            self.cprinter.logger.debug(final)
            return final
        except Exception as e:
            self.cprinter.logger.error(e)
            traceback.print_exc()



if __name__ == "__main__":
    parser  = argparse.ArgumentParser(description="CredsCheckr")
    parser.add_argument('-u', '--url', help="URL of target authentication page", required=True)
    parser.add_argument('--host', help="Selenium host", required=True)
    parser.add_argument('-p', '--port', help="Selenium port", required=True)
    parser.add_argument('-c', '--credentials', help="Credential list. username:password format, one by line", required=True)
    args = parser.parse_args()
    url = args.url
    host = args.host
    port = args.port
    credentials = args.credentials
    logger = logging.getLogger('credscheckr')
    logger.setLevel(logging.WARNING)
    sh = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
            '[%(asctime)s][%(module)s][%(funcName)s][%(levelname)s] %(message)s')
    sh.setFormatter(formatter)
    logger.addHandler(sh)
    try:
        driver = selenium_start()
        analyze_url(url, credentials, host, port)
    finally:
        for id in docker_ids:
            remove_container(id)

