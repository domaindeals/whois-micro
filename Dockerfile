FROM tiangolo/uwsgi-nginx-flask:python3.8-alpine
RUN apk update && apk add whois proxychains-ng
RUN mv /usr/bin/whois /usr/bin/whois-orig
COPY . .
RUN pip3 install -r requirements.txt
