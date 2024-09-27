FROM python:3.10.12-alpine3.18

WORKDIR /usr/app

ADD requirements.lock .
RUN pip install -r requirements.lock

ADD bouncer.py .

CMD [ "python", "/usr/app/bouncer.py", "/usr/app/config.ini" ]
