"""Regression tests against isolated running relays, never in-process Flask clients."""
from copy import deepcopy

from auth_client import user_id
from conftest import HTTPClient
from test_prekeys import bundle, headers


def test_bad_first_page_can_be_skipped_and_quarantined_without_false_receipts(raw_client):
    sender, recipient = user_id("poison"), user_id("target")
    sending, receiving = headers(raw_client, sender), headers(raw_client, recipient)
    ids = [f"{number:032x}" for number in range(501)]
    for number, message_id in enumerate(ids):
        assert raw_client.post("/send", headers=sending, json={"id": message_id, "sender": sender,
            "recipient": recipient, "ciphertext": "0100" if number < 500 else "later-message"}).status_code == 201
    first = raw_client.get(f"/messages/{recipient}", headers=receiving).json()["messages"]
    assert len(first) == 500
    later = raw_client.get(f"/messages/{recipient}?after={first[-1]['cursor']}", headers=receiving).json()["messages"]
    assert [message["id"] for message in later] == [ids[-1]]
    assert raw_client.post(f"/messages/{recipient}/ack", headers=receiving,
        json={"ids": ids[:500], "quarantine": True}).json()["acknowledged"] == 500
    assert [message["id"] for message in raw_client.get(f"/messages/{recipient}", headers=receiving).json()["messages"]] == [ids[-1]]
    statuses = raw_client.get(f"/statuses/{sender}", headers=sending).json()["statuses"]
    assert all(message["state"] == "sent" for message in statuses)
    # Explicit acceptance after local quarantine can still produce a real receipt.
    assert raw_client.post(f"/messages/{recipient}/ack", headers=receiving,
        json={"ids": [ids[0]]}).json()["acknowledged"] == 1
    assert raw_client.get(f"/statuses/{sender}", headers=sending).json()["statuses"][0]["state"] == "received"


def test_unknown_senders_cannot_take_capacity_reserved_for_contacts(raw_client):
    recipient, stranger, friend = [user_id(name) for name in ("target", "stranger", "friend")]
    receiving = headers(raw_client, recipient)
    assert raw_client.post(f"/messages/{recipient}/policy", headers=receiving,
        json={"contacts": [friend], "blocked": []}).status_code == 200
    unknown = headers(raw_client, stranger)
    for number in range(2):
        assert raw_client.post("/send", headers=unknown, json={"id":f"{number:032x}","sender":stranger,"recipient":recipient,"ciphertext":"opaque"}).status_code == 201
    assert raw_client.post("/send", headers=unknown, json={"sender":stranger,"recipient":recipient,"ciphertext":"opaque"}).status_code == 429
    assert raw_client.post("/send", headers=headers(raw_client, friend), json={"sender":friend,"recipient":recipient,"ciphertext":"friend"}).status_code == 201
    assert raw_client.post(f"/messages/{recipient}/policy", headers=receiving,
        json={"contacts":[friend],"blocked":[stranger]}).status_code == 200
    assert raw_client.post("/send", headers=unknown, json={"sender":stranger,"recipient":recipient,"ciphertext":"opaque"}).status_code == 409
    assert all(message["from"] == friend for message in raw_client.get(f"/messages/{recipient}",headers=receiving).json()["messages"])


def test_old_publication_cannot_restore_deleted_keys_after_new_revision(raw_client):
    owner, sender = user_id("owner"), user_id("sender")
    auth, claiming = headers(raw_client,owner),headers(raw_client,sender)
    original=bundle(owner,1)
    receipt=raw_client.post("/prekeys",json=original,headers=auth)
    assert receipt.status_code==200
    assert receipt.json()["publication_id"]==original["publication_id"]
    assert raw_client.post(f"/prekeys/{owner}/claim",json={},headers=claiming).json()["one_time_prekey"] is not None
    assert raw_client.post("/prekeys",json=original,headers=auth).json()==receipt.json()
    assert raw_client.get("/prekeys/status",headers=auth).json()["available"]==0
    following=deepcopy(original)
    following["revision"]=2;following["publication_id"]="b"*32
    following["one_time_prekeys"][0]["id"]="00000002"+"0"*24
    assert raw_client.post("/prekeys",json=following,headers=auth).status_code==200
    assert raw_client.post("/prekeys",json=original,headers=auth).status_code==409
    assert raw_client.get("/prekeys/status",headers=auth).json()["available"]==1
    invalid=deepcopy(following);invalid["revision"]=3
    assert raw_client.post("/prekeys",json=invalid,headers=auth).status_code==400


def test_prekey_global_quota_and_owner_quota_are_enforced(server_factory):
    server=server_factory(PREKEY_GLOBAL_LIMIT=2,PREKEY_OWNER_LIMIT=1)
    client=HTTPClient(server.port)
    first,second=user_id("first"),user_id("second")
    auth=headers(client,first)
    assert client.post("/prekeys",json=bundle(first,3),headers=auth).status_code==429
    assert client.post("/prekeys",json=bundle(first,2),headers=auth).status_code==200
    assert client.post("/prekeys",json=bundle(second,0),headers=headers(client,second)).status_code==429


def test_fresh_directory_accepts_existing_phone_revision(raw_client):
    owner=user_id("existing-phone")
    upload=bundle(owner,1)
    upload["revision"]=17
    upload["one_time_prekeys"][0]["id"]="00000011"+"0"*24
    assert raw_client.post("/prekeys",json=upload,headers=headers(raw_client,owner)).status_code==200
    assert raw_client.get("/prekeys/status",headers=headers(raw_client,owner)).json()["revision"]==17


def test_oversized_ciphertext_and_invalid_cursor_are_rejected(raw_client):
    sender,recipient=user_id("sender"),user_id("recipient")
    assert raw_client.post("/send",headers=headers(raw_client,sender),json={"sender":sender,
        "recipient":recipient,"ciphertext":"x"*(256*1024+1)}).status_code==413
    assert raw_client.get(f"/messages/{recipient}?after=-1",headers=headers(raw_client,recipient)).status_code==400
