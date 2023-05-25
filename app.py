from flask import Flask, jsonify, make_response
from datetime import date, datetime
import os
import whoisdomain as whois

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

@app.route("/")
def index():
    return "WhoIs micro service"


@app.route("/tlds")
def list_tlds():
    return jsonify(
        status='ok',
        data=whois.validTlds(),
    )


@app.route('/lookup/<domain>')
def lookup_whois(domain):
    try:
        override_rs = whois.ZZ["rs"]
        override_rs["registrant"] = r"Registrant:\s?(.+)"

        whois.mergeExternalDictWithRegex({
            "rs": override_rs
        })

        domain = whois.query(domain, include_raw_whois_text=True, ignore_returncode=True, simplistic=True, verbose=True)

        if domain is None:
            return jsonify(
                status='error',
                error='none',
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

        if isinstance(domain.status, list):
            domain.status = domain.status[0]

        return jsonify(
            status='ok',
            data={
                "domain_name": domain.name,
                "registrar": domain.registrar,
                "registrant": domain.registrant,
                "creation_date": domain_creation_date,
                "expiration_date": domain_expiration_date,
                "name_servers": domain.name_servers,
                "status": domain.status,
                "org": None,
                "emails": None,
            },
            data_full=domain.__dict__,
            raw=domain.text,
        )

    except whois.WhoisQuotaExceeded as e:
        return jsonify(
            status='error',
            error='quota',
            raw=str(e),
        )

    except whois.UnknownTld as e:
        return jsonify(
            status='error',
            error='unknown_tld',
            raw=str(e),
        )

    except (whois.FailedParsingWhoisOutput, whois.UnknownDateFormat, whois.WhoisCommandFailed) as e:
        return jsonify(
            status='error',
            error='internal',
            raw=str(e),
        )

    except Exception as e:
        return make_response(str(e), 500)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
