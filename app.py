from flask import Flask, jsonify, make_response
from datetime import date, datetime
import os
import whois
import json

app = Flask(__name__)

@app.route("/")
def index():
  return "WhoIs micro service"

@app.route("/tlds")
def list_tlds():
  return jsonify(
    status = 'ok', 
    data = whois.validTlds(),
  )

@app.route('/lookup/<domain>')
def lookup_whois(domain):
  try:
    domain = whois.query(domain)

    if domain is None:
      return jsonify(
        status = 'error',
        error = 'none',
      )

    if isinstance(domain.creation_date, (datetime, date)):
      domain_creation_date = domain.creation_date.isoformat()
    else:
      domain_creation_date = domain.creation_date

    if isinstance(domain.expiration_date, list):
      domain.expiration_date = domain.expiration_date[0]

    if isinstance(domain.expiration_date, (datetime, date)):
      domain_expiration_date = domain.expiration_date.isoformat()
    else:
      domain_expiration_date = domain.expiration_date

    # if domain.org is None:
      # domain.org = domain.registrant_organization

    if isinstance(domain.status, list):
      domain.status = domain.status[0]

    return jsonify(
      status = 'ok',
      data = {
        "domain_name": domain.name,
        "registrar": domain.registrar,
        "creation_date": domain_creation_date,
        "expiration_date": domain_expiration_date,
        "name_servers": domain.name_servers,
        "status": domain.status,
        "org": None,
        "emails": None,
      },
      raw = domain.__dict__,
    )
  except whois.parser.PywhoisError as e:
    return jsonify(
      status = 'error',
      error = str(e),
    )

  except Exception:
    return make_response('', 500)

if __name__ == "__main__":
  app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
