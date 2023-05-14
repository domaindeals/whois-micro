FROM tiangolo/uwsgi-nginx-flask:python3.8-alpine
RUN apk update && apk add whois
COPY . .
RUN pip3 install -r requirements.txt
