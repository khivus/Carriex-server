"""Group authorization tests through an actual localhost HTTP server."""
import base64
import copy
import hashlib
import sqlite3
import uuid
from pathlib import Path

import pytest
from auth_client import public_key, sign_group_state, user_id


def signing_bytes(s):
    name = base64.b64encode(s["name"].encode()).decode()
    fields = [s["id"], str(s["revision"]), str(s["epoch"]), s["previous"], s["admin"], name,
              ",".join(s["members"]), ",".join(s["invited"]), s["actor"], s["action"], s["target"], str(int(s["closed"]))]
    return ("Carriex group state v1\n" + "\n".join(fields) + "\n").encode("ascii")


def signed(s, actor):
    s["actor"] = actor
    s["auth_key"] = public_key(actor)
    s["signature"] = sign_group_state(actor, signing_bytes(s))
    return s


def create(admin):
    return signed(dict(version=1, id=uuid.uuid4().hex, revision=1, epoch=1, previous="0" * 64,
                       admin=admin, name="Practice group", members=[admin], invited=[], actor=admin,
                       action="create", target="", closed=False), admin)


def change(old, actor, action, target=""):
    s = copy.deepcopy(old)
    s.update(revision=old["revision"] + 1, previous=hashlib.sha256(signing_bytes(old)).hexdigest(), action=action, target=target)
    if action == "invite":
        s["invited"].append(target)
    elif action == "join":
        s["invited"].remove(target)
        s["members"].append(target)
    elif action == "remove":
        (s["members"] if target in s["members"] else s["invited"]).remove(target)
    elif action == "leave":
        s["members"].remove(target)
    elif action == "decline":
        s["invited"].remove(target)
    elif action == "close":
        s.update(members=[], invited=[], closed=True)
    s["members"].sort()
    s["invited"].sort()
    s["epoch"] += s["members"] != old["members"]
    return signed(s, actor)


@pytest.fixture
def actors(raw_client, sessions):
    def request(actor, method, path, body=None):
        return raw_client.request(method, path, json=body, headers={"Authorization": "Bearer " + sessions(actor)})
    return request


def apply(actors, state):
    response = actors(state["actor"], "POST", "/groups/state", state)
    assert response.status_code == 200, response.content
    return state


def invite_join(actors, state, person):
    state = apply(actors, change(state, state["admin"], "invite", person))
    return apply(actors, change(state, person, "join", person))


def distribute(actors, state, sender):
    body = dict(epoch=state["epoch"], packets=[dict(recipient=recipient, id=uuid.uuid4().hex,
        wire=base64.b64encode(b"opaque pairwise encrypted sender-key packet").decode())
        for recipient in state["members"] if recipient != sender])
    response = actors(sender, "POST", f"/groups/{state['id']}/keys", body)
    assert response.status_code == 200, response.content
    return body


def admission(joined, signer=None):
    admin = joined["admin"]
    proof = dict(version=1, group_id=joined["id"], member=joined["target"], revision=joined["revision"],
                 state_hash=hashlib.sha256(signing_bytes(joined)).hexdigest(), admin=admin, auth_key=public_key(signer or admin))
    data = (f"Carriex group admission v1\n{proof['group_id']}\n{proof['member']}\n{proof['revision']}\n{proof['state_hash']}\n{admin}\n").encode("ascii")
    proof["signature"] = sign_group_state(signer or admin, data)
    return proof


def test_new_members_and_invitees_cannot_download_pre_join_events_even_with_old_cursors(actors):
    admin, old, new = [user_id(label) for label in ("privacy-admin", "former-person", "new-person")]
    state = invite_join(actors, apply(actors, create(admin)), old)
    state = apply(actors, change(state, old, "leave", old))
    invited = apply(actors, change(state, admin, "invite", new))
    path = f"/groups/{state['id']}"
    before = actors(new, "GET", path + "/events?after=0").json()
    assert before["protocol"] == 2 and before["events"] == [] and before["periods"] == []
    assert before["invitation"] == invited
    assert old not in str(before)  # No old actor, removed roster, or invitation is sent.
    proposal = actors(new, "GET", path + "/join-proposal").json()["state"]
    assert proposal["action"] == "join" and proposal["actor"] == proposal["target"] == new
    assert old not in str(proposal)
    joined = apply(actors, signed(proposal, new))
    for cursor in (0, 1, joined["revision"] - 1):
        response = actors(new, "GET", path + f"/events?after={cursor}").json()
        assert response["events"] == [joined]
        assert response["periods"] == [dict(first_revision=joined["revision"], last_revision=None)]
        assert old not in str(response)
    assert actors(old, "GET", path + "/join-proposal").status_code == 403
    admin_events = actors(admin, "GET", path + "/events").json()["events"]
    assert admin_events[0]["action"] == "create" and len(admin_events) == joined["revision"]


def test_rejoining_does_not_grant_history_from_absence_and_terminal_event_is_visible(actors):
    admin, bob, carol = [user_id(label) for label in ("period-admin", "period-bob", "period-carol")]
    joined = invite_join(actors, apply(actors, create(admin)), bob)
    left = apply(actors, change(joined, bob, "leave", bob))
    gap = invite_join(actors, left, carol)
    reinvited = apply(actors, change(gap, admin, "invite", bob))
    path = f"/groups/{joined['id']}/events"
    assert [s["revision"] for s in actors(bob, "GET", path).json()["events"]] == [joined["revision"], left["revision"]]
    rejoined = apply(actors, change(reinvited, bob, "join", bob))
    removed = apply(actors, change(rejoined, admin, "remove", bob))
    later = apply(actors, change(removed, carol, "leave", carol))
    expected = [joined["revision"], left["revision"], rejoined["revision"], removed["revision"]]
    response = actors(bob, "GET", path + "?after=0").json()
    assert [s["revision"] for s in response["events"]] == expected
    assert later["revision"] not in expected and gap["revision"] not in expected
    assert actors(bob, "GET", path + f"?after={left['revision']}").json()["events"] == [rejoined, removed]


def test_invitee_can_decline_after_hidden_changes_without_downloading_them(actors):
    admin, bob, carol = [user_id(label) for label in ("decline-admin", "decline-bob", "decline-carol")]
    state = apply(actors, create(admin))
    invitation = apply(actors, change(state, admin, "invite", bob))
    state = invite_join(actors, invitation, carol)
    state = apply(actors, change(state, carol, "leave", carol))
    path = f"/groups/{state['id']}"
    assert actors(bob, "GET", path + "/events").json()["events"] == []
    proposal = actors(bob, "GET", path + "/decline-proposal").json()["state"]
    assert proposal["action"] == "decline" and proposal["target"] == proposal["actor"] == bob
    assert proposal["members"] == [admin] and proposal["invited"] == []
    assert carol not in str(proposal)
    terminal = apply(actors, signed(proposal, bob))
    response = actors(bob, "GET", path + "/events").json()
    assert response["events"] == [] and response["terminal"] == terminal
    assert actors(bob, "GET", path + "/decline-proposal").status_code == 403


def test_admin_admission_binds_exact_join_and_is_returned_only_to_joining_device(actors):
    admin, bob, outsider = [user_id(label) for label in ("admission-admin", "admission-bob", "admission-outsider")]
    joined = invite_join(actors, apply(actors, create(admin)), bob)
    path = f"/groups/{joined['id']}"
    proof = admission(joined)
    assert actors(bob, "POST", path + "/admissions", dict(admissions=[proof])).status_code == 403
    assert actors(admin, "POST", path + "/admissions", dict(admissions=[admission(joined, outsider)])).status_code == 403
    altered = dict(proof, state_hash="0" * 64)
    assert actors(admin, "POST", path + "/admissions", dict(admissions=[altered])).status_code == 409
    for _ in range(2):
        assert actors(admin, "POST", path + "/admissions", dict(admissions=[proof])).status_code == 200
    assert actors(bob, "GET", path + "/events").json()["admissions"] == [proof]
    assert actors(admin, "GET", path + "/events").json()["admissions"] == []
    assert actors(outsider, "GET", path + "/events").status_code == 403


def test_history_filter_applies_before_pagination(actors):
    admin, former, new = [user_id(label) for label in ("page-admin", "page-former", "page-new")]
    state = apply(actors, create(admin))
    for _ in range(51):
        state = apply(actors, change(state, admin, "invite", former))
        state = apply(actors, change(state, admin, "remove", former))
    state = invite_join(actors, state, new)
    response = actors(new, "GET", f"/groups/{state['id']}/events?after=0").json()
    assert response["events"] == [state]
    assert former not in str(response)


def test_upgrade_reconstructs_private_history_boundaries_and_preserves_them_on_restart(server_factory):
    from auth_client import authenticate
    from conftest import HTTPClient
    server = server_factory()
    client = HTTPClient(server.port)
    tokens = {}

    def actors(actor, method, path, body=None):
        if actor not in tokens:
            tokens[actor] = authenticate(client, actor)
        return client.request(method, path, json=body, headers={"Authorization": "Bearer " + tokens[actor]})

    admin, old, new = [user_id(label) for label in ("upgrade-admin", "upgrade-old", "upgrade-new")]
    state = invite_join(actors, apply(actors, create(admin)), old)
    state = apply(actors, change(state, old, "leave", old))
    joined = invite_join(actors, state, new)
    server.stop()
    # An old database has signed events/access but no participation-period table.
    with sqlite3.connect(Path(server.config["MESSAGE_DATA_DIR"]) / "messages.sqlite3") as db:
        db.execute("DROP TABLE group_periods")
    for _ in range(2):
        server.start()
        tokens.clear()
        response = actors(new, "GET", f"/groups/{joined['id']}/events?after=0").json()
        assert response["events"] == [joined] and old not in str(response)
        server.stop()


def send(actors, state, sender, body=None):
    body = body or dict(epoch=state["epoch"], id=uuid.uuid4().hex, wire=base64.b64encode(b"signed encrypted group ciphertext").decode())
    return actors(sender, "POST", f"/groups/{state['id']}/messages", body), body


def test_admin_is_permanent_invitations_require_acceptance_and_changes_are_signed(actors):
    admin, bob, outsider = [user_id(label) for label in ("group-admin", "group-bob", "outsider")]
    state = apply(actors, create(admin))
    assert actors(outsider, "GET", f"/groups/{state['id']}/events").status_code == 403
    bad = change(state, outsider, "invite", bob)
    assert actors(outsider, "POST", "/groups/state", bad).status_code == 403
    invited = apply(actors, change(state, admin, "invite", bob))
    assert invited["epoch"] == state["epoch"]
    assert actors(bob, "GET", f"/groups/{state['id']}/keys").status_code == 403
    assert actors(bob, "GET", f"/groups/{state['id']}/messages").status_code == 403
    joined = apply(actors, change(invited, bob, "join", bob))
    assert joined["epoch"] == state["epoch"] + 1
    transfer = change(joined, admin, "invite", outsider)
    transfer["admin"] = bob
    signed(transfer, admin)
    assert actors(admin, "POST", "/groups/state", transfer).status_code == 403
    tamper = change(joined, admin, "remove", bob)
    tamper["epoch"] -= 1
    signed(tamper, admin)
    assert actors(admin, "POST", "/groups/state", tamper).status_code == 409
    forged = change(joined, admin, "remove", bob)
    forged["signature"] = sign_group_state(outsider, signing_bytes(forged))
    assert actors(admin, "POST", "/groups/state", forged).status_code == 403
    assert actors(admin, "POST", "/groups/state", change(joined, admin, "leave", admin)).status_code == 403
    removed = apply(actors, change(joined, admin, "remove", bob))
    assert actors(bob, "GET", f"/groups/{state['id']}/keys").status_code == 403
    newer = apply(actors, change(removed, admin, "invite", outsider))
    visible = actors(bob, "GET", f"/groups/{state['id']}/events").json()["events"]
    assert visible[-1]["revision"] == removed["revision"] < newer["revision"]
    closed = apply(actors, change(newer, admin, "close"))
    assert send(actors, closed, admin)[0].status_code == 403


def test_membership_changes_force_all_senders_to_redistribute_and_exclude_removed_members(actors):
    admin, bob, carol = [user_id(label) for label in ("sender-admin", "sender-bob", "sender-carol")]
    state = invite_join(actors, apply(actors, create(admin)), bob)
    response, first = send(actors, state, admin)
    assert response.status_code == 409
    packets = distribute(actors, state, admin)
    assert actors(admin, "POST", f"/groups/{state['id']}/keys", packets).status_code == 200
    replacement = copy.deepcopy(packets)
    replacement["packets"][0]["id"] = uuid.uuid4().hex
    assert actors(admin, "POST", f"/groups/{state['id']}/keys", replacement).status_code == 409
    distribute(actors, state, bob)
    response, first = send(actors, state, admin)
    assert response.status_code == 200
    assert send(actors, state, admin, first)[0].status_code == 200
    inbox = actors(bob, "GET", f"/groups/{state['id']}/messages").json()["messages"]
    assert [message["id"] for message in inbox] == [first["id"]]
    state = invite_join(actors, state, carol)
    for sender in state["members"]:
        assert send(actors, state, sender)[0].status_code == 409
        assert actors(sender, "GET", f"/groups/{state['id']}/keys").json()["packets"] == []
    assert actors(carol, "GET", f"/groups/{state['id']}/messages").json()["messages"] == []
    assert actors(bob, "GET", f"/groups/{state['id']}/messages").json()["messages"][0]["id"] == first["id"]
    assert actors(bob, "GET", f"/groups/{state['id']}/keys?epoch=2").json()["packets"]
    assert actors(carol, "GET", f"/groups/{state['id']}/keys?epoch=2").json()["packets"] == []
    for sender in state["members"]:
        distribute(actors, state, sender)
    response, shared = send(actors, state, bob)
    assert response.status_code == 200
    for recipient in (admin, carol):
        inbox = actors(recipient, "GET", f"/groups/{state['id']}/messages").json()["messages"]
        assert inbox[0]["wire"] == shared["wire"]  # One ciphertext, fan-out to recipients.
        assert actors(recipient, "POST", f"/groups/{state['id']}/ack", {"ids": [shared["id"]]}).status_code == 200
    assert actors(bob, "GET", f"/groups/{state['id']}/statuses").json()["statuses"][0]["state"] == "received"
    old = state
    state = apply(actors, change(state, bob, "leave", bob))
    assert state["epoch"] == old["epoch"] + 1
    assert send(actors, state, bob)[0].status_code == 403
    assert send(actors, old, admin)[0].status_code == 409
    for sender in state["members"]:
        assert send(actors, state, sender)[0].status_code == 409
        distribute(actors, state, sender)
        assert send(actors, state, sender)[0].status_code == 200


def test_invitations_and_group_messages_contribute_to_private_background_counts(actors):
    admin, bob = [user_id(label) for label in ("count-group-admin", "count-group-bob")]
    state = apply(actors, create(admin))
    state = apply(actors, change(state, admin, "invite", bob))
    count = actors(bob, "GET", f"/messages/{bob}/count").json()
    assert count["pending_count"] == 1
    state = apply(actors, change(state, bob, "join", bob))
    assert actors(bob, "GET", f"/messages/{bob}/count").json()["pending_count"] == 0
    distribute(actors, state, admin)
    response, message = send(actors, state, admin)
    assert response.status_code == 200
    updated = actors(bob, "GET", f"/messages/{bob}/count").json()
    assert updated["pending_count"] == 1 and updated["revision"] > count["revision"]
    actors(bob, "POST", f"/groups/{state['id']}/ack", {"ids": [message["id"]]})
    assert actors(bob, "GET", f"/messages/{bob}/count").json()["pending_count"] == 0


def test_removal_does_not_report_an_unacknowledged_message_as_received(actors):
    admin, bob = [user_id(label) for label in ("receipt-group-admin", "receipt-group-bob")]
    state = invite_join(actors, apply(actors, create(admin)), bob)
    distribute(actors, state, admin)
    response, message = send(actors, state, admin)
    assert response.status_code == 200
    state = apply(actors, change(state, admin, "remove", bob))
    status = actors(admin, "GET", f"/groups/{state['id']}/statuses").json()["statuses"]
    assert next(entry for entry in status if entry["id"] == message["id"])["state"] == "sent"


def test_acknowledged_ciphertext_is_cleared_but_exact_submission_retry_stays_idempotent(actors):
    admin, bob = [user_id(label) for label in ("retry-group-admin", "retry-group-bob")]
    state = invite_join(actors, apply(actors, create(admin)), bob)
    distribute(actors, state, admin)
    response, message = send(actors, state, admin)
    assert response.status_code == 200
    actors(bob, "POST", f"/groups/{state['id']}/ack", {"ids": [message["id"]]})
    assert send(actors, state, admin, message)[0].status_code == 200
    assert actors(bob, "GET", f"/groups/{state['id']}/messages").json()["messages"] == []
    changed = dict(message, wire=base64.b64encode(b"different ciphertext").decode())
    assert send(actors, state, admin, changed)[0].status_code == 409


@pytest.mark.parametrize("field,value", [("action", []), ("members", [None]), ("version", True), ("epoch", True), ("signature", "invalid")])
def test_malformed_membership_does_not_crash_server(actors, field, value):
    admin = user_id("bad-group-admin")
    s = create(admin)
    s[field] = value
    assert actors(admin, "POST", "/groups/state", s).status_code in (400, 403)
