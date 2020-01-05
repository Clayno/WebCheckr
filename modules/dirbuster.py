def gobuster(url, wordlist, directory):
    """
    Launch Gobuster docker.

    Args:
        url (str): URL to bruteforce
    """
    print("[i] Bruteforcing directories/files in background")
    path, filename = os.path.split(wordlist)
    try:
        # Directory bruteforce with force wildcards without checking certificate
        command = commands["Gobuster"].format("/wordlists/".format(filename), url)
        client = docker.from_env()
        container = client.containers.run(images["Gobuster"], command, detach=True,
                volumes={path: {'bind': '/wordlists', 'mode': 'ro'}},
                auto_remove=True)
        for line in container.logs(stream=True):
            cprinter.cprint(line.decode().strip(), "gobuster.txt", url=url)
    except:
        remove_container(container)

