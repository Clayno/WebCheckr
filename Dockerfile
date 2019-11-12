FROM python:3-alpine

COPY . /webcheckr
WORKDIR /webcheckr
RUN chmod -R 777 /webcheckr
RUN pip install --upgrade pip && pip install -r requirements.txt

ENTRYPOINT ["python", "webcheckr.py"]
