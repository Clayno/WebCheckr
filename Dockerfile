FROM python:3.7-alpine

# Installing gcc for alpine
RUN apk update && apk upgrade \
	&& apk add --no-cache gcc\
			libc-dev \
	&& rm -rf /var/cache/apk/*
# Copying files and running pip
COPY requirements.txt /webcheckr/
WORKDIR /webcheckr
RUN pip install --upgrade pip && pip install -r requirements.txt
COPY . /webcheckr
RUN chmod -R 777 /webcheckr

ENTRYPOINT ["python", "webcheckr.py"]
