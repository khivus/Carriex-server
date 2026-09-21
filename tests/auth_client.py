"""Independent wire-protocol client for localhost tests; no application imports."""
import base64
import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


_labels = {}
_keys = {}
_audiences = {}


def remember_challenge(payload):
    _audiences[payload["challenge"]] = payload["audience"]
    return payload["challenge"]


def user_id(label):
    if label not in _labels:
        key = ec.generate_private_key(ec.SECP256R1())
        encoded = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        identity = hashlib.sha256(encoded).hexdigest()
        _labels[label] = identity
        _keys[identity] = key
    return _labels[label]


def public_key(identity):
    return base64.b64encode(_keys[identity].public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )).decode("ascii")


def sign(identity, challenge, claimed_id=None, audience=None):
    origin = audience if audience is not None else _audiences[challenge]
    payload = f"Carriex device authentication v1\n{origin}\n{claimed_id or identity}\n{challenge}"
    return base64.b64encode(_keys[identity].sign(
        payload.encode("ascii"), ec.ECDSA(hashes.SHA256()),
    )).decode("ascii")


def authenticate(client, identity):
    response = client.post("/auth/challenge", json={"public_key": public_key(identity)})
    assert response.status_code == 200, response.content
    challenge = response.json()
    remember_challenge(challenge)
    assert challenge["user_id"] == identity
    response = client.post("/auth/verify", json={
        "challenge": challenge["challenge"], "signature": sign(identity, challenge["challenge"]),
    })
    assert response.status_code == 200, response.content
    assert response.json()["user_id"] == identity
    return response.json()["token"]
