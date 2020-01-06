#!/bin/bash
WEBCHECKR_FILE='/usr/local/bin/webcheckr'

function cleanup {
    sudo rm ${WEBCHECKR_FILE}
}

if [ -f "${WEBCHECKR_FILE}" ]
then
    echo "An installation already exists. This will remove the existing files."
    echo "Do you want to continue ?"
    select yn in "Yes" "No"; do
        case $yn in
            Yes ) cleanup; break;;
            No ) exit;;
        esac
    done
fi

echo "Configuring dockers"
if [ ! -f "Dockerfile" ]
then
    echo "Wrong directory, go to the cloned WebChekr repository root"
    exit
fi
docker network create webcheckr
docker build -t webcheckr .
docker create --net=webcheckr --name cvesearch_docker ttimasdf/cve-search:withdb
docker pull selenium/standalone-chrome
docker pull wappalyzer/cli
docker pull clayno/dirsearch

echo "Creating file in /usr/local/bin/webcheckr (need sudo)"
sudo tee -a ${WEBCHECKR_FILE}<<EOF
#!/bin/bash

docker run --rm -it -v /var/run/docker.sock:/var/run/docker.sock -v /tmp/webcheckr:/tmp/output -v \${PWD}:/webcheckr/shared --user \$(id -u):\$(id -g) --group-add \$(stat -c '%g' /var/run/docker.sock) --net webcheckr webcheckr \$@

EOF
sudo chmod +x ${WEBCHECKR_FILE}

echo "Finished"
