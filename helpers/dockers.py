import docker
import string
import random

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

def id_generator(size=6, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choices(chars, k=size))

def docker_wrapper(image, command="", **kwargs):
    client = docker.from_env()
    container = client.containers.run(image,
            command,
            name="webcheckr_{id}".format(id=id_generator()),
            network="webcheckr",
            detach=True,
            auto_remove=True,
            **kwargs)
    return container

def cleanup_webcheckr_dockers():
    client = docker.from_env()
    while client.containers.list(filters={'name': 'webcheckr_'}):
        print("Containers found, killing them")
        for container in client.containers.list(filters={'name': 'webcheckr_'}):
            remove_container(container)
