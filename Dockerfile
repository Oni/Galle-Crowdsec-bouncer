FROM python:3.10.12-alpine3.18

WORKDIR /usr/app

ADD bouncer.py .

RUN pip install -r requirements.lock

CMD [ "python", "/usr/app/bouncer.py", "/usr/app/config.ini" ]
