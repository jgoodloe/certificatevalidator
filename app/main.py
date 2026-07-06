"""
PIV / PIV-I / CAC certificate validator.

Receives the client certificate that the mutual-TLS nginx front-end captured
during the handshake, passed through as the URL-escaped X-Client-Cert header
(nginx $ssl_client_escaped_cert). Two modes:

  - details  : parse and display certificate fields (no trust/revocation)
  - validate : build a path to an FPKI trust anchor AND check revocation
               (OCSP first, CRL fallback) via pyhanko-certvalidator

The routing (which CAs the browser was offered) is decided at the nginx layer
by the piv vs piv-any vhost. This app only sees whatever cert the user picked.
"""

import os
import urllib.parse
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

# pyhanko-certvalidator does path building + OCSP + CRL in one library.
from pyhanko_certvalidator import CertificateValidator, ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore
from pyhanko_certvalidator.errors import PathValidationError, RevokedError

app = FastAPI(title="PIV Certificate Validator")

TRUST_DIR = os.environ.get("TRUST_DIR", "/trust/anchors")
INTERMEDIATE_DIR = os.environ.get("INTERMEDIATE_DIR", "/trust/intermediates")

# RBAC: the group a user must be in (per authentik) to use the validator.
# Enforced app-side as defence-in-depth on top of authentik's group binding.
REQUIRED_GROUP = os.environ.get("REQUIRED_GROUP", "piv-validator")
# authentik forwards groups as a separator-joined string; default is comma.
GROUP_SEPARATOR = os.environ.get("GROUP_SEPARATOR", ",")

# Federal PIV policy OIDs, for labelling in the details view.
PIV_POLICY_OIDS = {
    "2.16.840.1.101.3.2.1.3.6": "id-fpki-common-policy",
    "2.16.840.1.101.3.2.1.3.7": "id-fpki-common-hardware",
    "2.16.840.1.101.3.2.1.3.13": "id-fpki-common-authentication",
    "2.16.840.1.101.3.2.1.3.16": "id-fpki-common-high",
    "2.16.840.1.101.3.2.1.3.18": "id-fpki-common-piv-contentSigning",
    "2.16.840.1.101.3.2.1.3.40": "id-fpki-common-derived-pivAuth",
    "2.16.840.1.101.3.2.1.3.41": "id-fpki-common-derived-pivAuth-hw",
    "2.16.840.1.101.3.2.1.3.45": "id-fpki-common-pivAuth-2",
}

# PIV NACI / FASC-N and UUID live in the SAN as otherName; PIV auth EKU:
PIV_AUTH_EKU = "2.16.840.1.101.3.6.6"


def _load_certs_from_dir(path):
    certs = []
    if not os.path.isdir(path):
        return certs
    for fn in os.listdir(path):
        full = os.path.join(path, fn)
        try:
            with open(full, "rb") as fh:
                data = fh.read()
            # Accept PEM (possibly multiple) or DER.
            if b"-----BEGIN CERTIFICATE-----" in data:
                for c in x509.load_pem_x509_certificates(data):
                    certs.append(c)
            else:
                certs.append(x509.load_der_x509_certificate(data))
        except Exception:
            continue
    return certs


def _check_rbac(request: Request):
    """Return (allowed, identity) based on the authentik-forwarded groups.

    The group header is set by the authentik outpost at the nginx auth_request
    hop and copied onto the upstream request. Because this container is only
    reachable through the controlled NPM Stream -> mtls-nginx path, the header
    cannot be forged by a direct client. If that assumption ever breaks, this
    check is worthless -- so keep the container off any public interface.
    """
    username = request.headers.get("x-authentik-username")
    email = request.headers.get("x-authentik-email")
    raw_groups = request.headers.get("x-authentik-groups", "")
    groups = [g.strip() for g in raw_groups.split(GROUP_SEPARATOR) if g.strip()]

    identity = {"username": username, "email": email, "groups": groups}

    # No identity header at all -> the request did not pass through the
    # authenticated hop. Deny.
    if not username:
        return False, identity

    allowed = REQUIRED_GROUP in groups
    return allowed, identity


def _read_client_cert(request: Request):
    """Pull the escaped PEM out of the nginx-set header and parse it."""
    raw = request.headers.get("x-client-cert")
    verify = request.headers.get("x-client-verify", "NONE")
    if not raw or raw == "-":
        return None, verify
    pem = urllib.parse.unquote(raw)
    try:
        cert = x509.load_pem_x509_certificate(pem.encode())
        return cert, verify
    except Exception:
        return None, verify


def _fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex(":").upper()


def _extract_details(cert: x509.Certificate) -> dict:
    d = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": format(cert.serial_number, "x").upper(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "sha256_fingerprint": _fingerprint(cert),
        "policies": [],
        "extended_key_usage": [],
        "san": [],
        "is_expired": datetime.now(timezone.utc) > cert.not_valid_after_utc,
    }

    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        d["common_name"] = cn[0].value if cn else None
    except Exception:
        d["common_name"] = None

    try:
        pol = cert.extensions.get_extension_for_oid(
            ExtensionOID.CERTIFICATE_POLICIES
        ).value
        for p in pol:
            oid = p.policy_identifier.dotted_string
            d["policies"].append(
                {"oid": oid, "name": PIV_POLICY_OIDS.get(oid, "unknown")}
            )
    except x509.ExtensionNotFound:
        pass

    try:
        eku = cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        ).value
        for e in eku:
            d["extended_key_usage"].append(
                {
                    "oid": e.dotted_string,
                    "piv_auth": e.dotted_string == PIV_AUTH_EKU,
                }
            )
    except x509.ExtensionNotFound:
        pass

    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        for name in san:
            d["san"].append(f"{type(name).__name__}: {name.value!r}")
    except x509.ExtensionNotFound:
        pass

    # Heuristic credential-type flag for display.
    policy_names = {p["name"] for p in d["policies"]}
    has_piv_eku = any(e["piv_auth"] for e in d["extended_key_usage"])
    if has_piv_eku or any("piv" in n for n in policy_names):
        d["credential_type"] = "PIV / PIV-I / Derived PIV (heuristic)"
    else:
        d["credential_type"] = "Non-PIV client certificate"

    return d


def _validate(cert: x509.Certificate) -> dict:
    """Path-build to an FPKI anchor and check revocation (OCSP, then CRL)."""
    anchors = _load_certs_from_dir(TRUST_DIR)
    if not anchors:
        return {
            "result": "ERROR",
            "reason": "No trust anchors loaded. Populate TRUST_DIR with FPKI "
            "(or NIST test) root certificates.",
        }

    intermediates = _load_certs_from_dir(INTERMEDIATE_DIR)
    store = SimpleCertificateStore()
    for c in intermediates:
        store.register(c)

    vc = ValidationContext(
        trust_roots=anchors,
        other_certs=intermediates,
        allow_fetching=True,          # fetch AIA/CRL over the network
        revocation_mode="hard-fail",  # a cert with no reachable revocation info fails
    )

    validator = CertificateValidator(
        cert, intermediate_certs=intermediates, validation_context=vc
    )

    try:
        path = validator.validate_usage(key_usage=set())
        chain = [c.subject.human_friendly for c in path]
        return {
            "result": "VALID",
            "reason": "Chain built to a trusted FPKI anchor and no certificate "
            "in the path is revoked.",
            "path_length": len(path),
            "chain": chain,
        }
    except RevokedError as e:
        return {"result": "INVALID", "reason": f"Certificate revoked: {e}"}
    except PathValidationError as e:
        return {"result": "INVALID", "reason": f"Path validation failed: {e}"}
    except Exception as e:
        return {"result": "ERROR", "reason": f"{type(e).__name__}: {e}"}


@app.get("/debug")
async def debug(request: Request, certDetailsOnly: str | None = None):
    # RBAC gate: must be an authenticated member of REQUIRED_GROUP to do
    # ANYTHING here -- details view included. This is the "RBAC gates the
    # validator entirely" posture.
    allowed, identity = _check_rbac(request)
    if not allowed:
        return JSONResponse(
            status_code=403,
            content={
                "result": "FORBIDDEN",
                "reason": (
                    f"Access requires membership in the '{REQUIRED_GROUP}' "
                    "group. If you just logged in, return to the landing page "
                    "and start from there."
                ),
                "identity": {
                    "username": identity["username"],
                    "groups": identity["groups"],
                },
            },
        )

    cert, verify = _read_client_cert(request)

    details_only = certDetailsOnly is not None

    who = {"username": identity["username"], "email": identity["email"]}

    if cert is None:
        payload = {
            "result": "NONE",
            "reason": "No certificate provided by the browser.",
            "nginx_verify": verify,
            "authenticated_user": who,
        }
        return _render(payload, details_only)

    details = _extract_details(cert)

    if details_only:
        payload = {
            "mode": "details",
            "certificate": details,
            "nginx_verify": verify,
            "authenticated_user": who,
        }
    else:
        result = _validate(cert)
        payload = {
            "mode": "validate",
            "certificate": details,
            "validation": result,
            "nginx_verify": verify,
            "authenticated_user": who,
        }

    return _render(payload, details_only)


def _render(payload: dict, details_only: bool):
    # Content negotiation: JSON for API callers, HTML otherwise.
    return JSONResponse(payload)


@app.get("/healthz")
async def healthz():
    return {"ok": True, "anchors_loaded": len(_load_certs_from_dir(TRUST_DIR))}
