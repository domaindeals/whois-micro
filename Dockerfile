FROM tiangolo/uwsgi-nginx-flask:python3.11
RUN apt-get update && apt-get install -y ntp whois proxychains-ng
RUN mv /usr/bin/whois /usr/bin/whois-orig
COPY . .
RUN pip3 install -r requirements.txt
