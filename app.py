from flask import Flask, json, jsonify, make_response
from datetime import date, datetime
import os
import whoisdomain as whois

app = Flask(__name__)

override_rs = whois.ZZ["rs"]
override_rs["registrant"] = r"Registrant:\s?(.+)"

whois.mergeExternalDictWithRegex({
    "rs": override_rs,
    # RNIDS
    "срб": {"extend": "rs"},
    "xn--90a3ac": {"extend": "rs"},  # срб

    "ac.rs": {"extend": "rs"},  # not a zone?
    "co.rs": {"extend": "rs"},
    "edu.rs": {"extend": "rs"},
    "gov.rs": {"extend": "rs"},  # not a zone?
    "in.rs": {"extend": "rs"},
    "org.rs": {"extend": "rs"},
})


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
        domain = whois.query(
            domain,
            include_raw_whois_text=True,
            ignore_returncode=True,
            simplistic=True,
            verbose=False,
            force=True,
        )

        if domain is None:
            return jsonify(
                status='error',
                error='none',
            )

        if isinstance(domain.creation_date, (datetime, date)):
            domain_creation_date = domain.creation_date.isoformat()
        else:
            domain_creation_date = domain.creation_date

        if isinstance(domain.last_updated, (datetime, date)):
            domain_last_updated = domain.last_updated.isoformat()
        else:
            domain_last_updated = domain.last_updated

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
                "domain_tld": domain.tld,
                "registrar": domain.registrar,
                "registrant": domain.registrant,
                "creation_date": domain_creation_date,
                "expiration_date": domain_expiration_date,
                "last_updated": domain_last_updated,
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
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5001)))
