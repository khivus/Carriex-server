"""Prekey API tests use real HTTP against an isolated server, including restarts."""
import base64
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

from auth_client import authenticate, public_key, sign_encryption_identity, user_id
from conftest import HTTPClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
import pytest


def encoded_key():
    return base64.b64encode(x25519.X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")


def bundle(identity, count=3):
    key = encoded_key()
    return {"version": 2, "revision":1,"publication_id":"a"*32, "identity_key": key, "auth_key": public_key(identity),
            "binding": sign_encryption_identity(identity, key),
            # The relay treats the XEdDSA signature as opaque; Android verifies it.
            "signed_prekey": {"id": "f" * 32, "key": encoded_key(), "signature": base64.b64encode(bytes(64)).decode("ascii")},
            "one_time_prekeys": [{"id": "00000001" + f"{number:024x}", "key": encoded_key()} for number in range(count)]}


def headers(client, identity):
    return {"Authorization": "Bearer " + authenticate(client, identity)}


def test_prekeys_require_auth_and_owner_binding(raw_client):
    alice, bob = user_id("alice"), user_id("bob")
    data = bundle(bob)
    assert raw_client.post("/prekeys", json=data).status_code == 401
    assert raw_client.post("/prekeys", json=data, headers=headers(raw_client, alice)).status_code == 400
    data["binding"] = base64.b64encode(bytes(70)).decode("ascii")
    assert raw_client.post("/prekeys", json=data, headers=headers(raw_client, bob)).status_code == 400


@pytest.mark.parametrize("field,value", [("version", 1), ("identity_key", "garbage"),
                                        ("one_time_prekeys", {}), ("auth_key", "AA==")])
def test_malformed_bundle_is_rejected(raw_client, field, value):
    bob = user_id("bob")
    data = bundle(bob)
    data[field] = value
    assert raw_client.post("/prekeys", json=data, headers=headers(raw_client, bob)).status_code == 400


def test_concurrent_claims_are_unique_and_upload_retry_does_not_resurrect(raw_client):
    alice, bob = user_id("alice"), user_id("bob")
    a, b = headers(raw_client, alice), headers(raw_client, bob)
    data = bundle(bob, 12)
    assert raw_client.post("/prekeys", json=data, headers=b).status_code == 200
    with ThreadPoolExecutor(max_workers=12) as pool:
        responses = list(pool.map(lambda _: raw_client.post(f"/prekeys/{bob}/claim", json={}, headers=a), range(12)))
    assert all(response.status_code == 200 for response in responses)
    assert len({response.json()["one_time_prekey"]["id"] for response in responses}) == 12
    assert raw_client.post("/prekeys", json=data, headers=b).status_code == 200
    assert raw_client.get("/prekeys/status", headers=b).json()["available"] == 0
    response = raw_client.post(f"/prekeys/{bob}/claim", json={}, headers=a)
    assert response.json()["one_time_prekey"] is None
    assert response.json()["identity_key"] == data["identity_key"]
    assert response.headers["Cache-Control"] == "no-store"


def test_directory_and_consumption_survive_restart(server_factory, tmp_path):
    first = server_factory(MESSAGE_DATA_DIR=str(tmp_path / "persistent-prekeys"))
    client = HTTPClient(first.port)
    alice, bob = user_id("alice"), user_id("bob")
    data = bundle(bob, 2)
    assert client.post("/prekeys", json=data, headers=headers(client, bob)).status_code == 200
    used = client.post(f"/prekeys/{bob}/claim", json={}, headers=headers(client, alice)).json()["one_time_prekey"]["id"]
    first.stop()
    second = server_factory(MESSAGE_DATA_DIR=str(tmp_path / "persistent-prekeys"))
    client = HTTPClient(second.port)
    assert client.post("/prekeys", json=data, headers=headers(client, bob)).status_code == 200
    next_key = client.post(f"/prekeys/{bob}/claim", json={}, headers=headers(client, alice)).json()["one_time_prekey"]["id"]
    assert used != next_key
    assert client.get("/prekeys/status", headers=headers(client, bob)).json()["available"] == 0


def test_identity_or_prekey_replacement_is_rejected(raw_client):
    bob = user_id("bob")
    owner = headers(raw_client, bob)
    data = bundle(bob)
    assert raw_client.post("/prekeys", json=data, headers=owner).status_code == 200
    changed = deepcopy(data)
    changed["one_time_prekeys"][0]["key"] = encoded_key()
    assert raw_client.post("/prekeys", json=changed, headers=owner).status_code == 409
    assert raw_client.post("/prekeys", json=bundle(bob), headers=owner).status_code == 409


def test_claim_limit_and_unknown_contacts(raw_client):
    alice, bob = user_id("alice"), user_id("bob")
    a, b = headers(raw_client, alice), headers(raw_client, bob)
    assert raw_client.post(f"/prekeys/{bob}/claim", json={}, headers=a).status_code == 404
    assert raw_client.post("/prekeys", json=bundle(bob, 0), headers=b).status_code == 200
    for _ in range(30):
        assert raw_client.post(f"/prekeys/{bob}/claim", json={}, headers=a).status_code == 200
    assert raw_client.post(f"/prekeys/{bob}/claim", json={}, headers=a).status_code == 429
