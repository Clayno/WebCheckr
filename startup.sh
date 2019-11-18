#!/bin/bash

echo "Configuring dockers"
docker network create webcheckr
docker build -t webcheckr .
docker create --net=webcheckr --name cvesearch_docker ttimasdf/cve-search:withdb

echo "Creating file in /usr/local/bin/webcheckr (need sudo)"
sudo tee -a /usr/local/bin/webcheckr<<EOF
#!/bin/bash

docker run --rm -it -v /var/run/docker.sock:/var/run/docker.sock -v \${PWD}:/webcheckr/data --user \$(id -u):\$(id -g) --group-add \$(stat -c '%g' /var/run/docker.sock) --net webcheckr webcheckr \$@

EOF
sudo chmod +x /usr/local/bin/webcheckr

echo "Finished"
