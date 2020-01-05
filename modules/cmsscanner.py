def cms_scanner(url, scanner, directory):
    """
    Launch the scanner for the found CMS on the url.

    Args:
        url (str): URL to scan
        scanner (str): CMS scanner
    """
    cprinter.cprint("[+] Launching {0}".format(scanner))
    try:
        client = docker.from_env()
        container = client.containers.run(images[scanner], commands[scanner].format(url), 
                detach=True, auto_remove=True)
        for line in container.logs(stream=True):
            cprinter.cprint(line.decode().strip(), "{0}.txt".format(scanner), url=url)
    finally:
        remove_container(container)

