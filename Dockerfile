FROM python:3.7

RUN apt-get update && apt-get install -y postgresql-client \
    gcc gettext \
    --no-install-recommends && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip

COPY ./requirements.txt /requirements.txt

RUN pip install -r /requirements.txt

COPY ./api /srv/www/api
