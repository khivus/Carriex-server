"""Count-only notification API exercised through a real localhost relay."""
import hashlib
import sqlite3
import time

from auth_client import user_id
from conftest import HTTPClient
from test_prekeys import headers


def credential(client, owner):
    response = client.post('/notifications/token', headers=headers(client, owner), json={})
    assert response.status_code == 200
    data = response.json()
    assert data['scope'] == 'notifications.count' and data['user_id'] == owner
    assert len(data['token']) == 43
    return {'Authorization': 'Bearer ' + data['token']}


def send(client, sender, recipient, number):
    message = dict(id=f'{number:032x}', sender=sender, recipient=recipient, ciphertext='opaque-contents')
    assert client.post('/send', headers=headers(client, sender), json=message).status_code == 201
    return message


def count(client, owner, auth):
    response = client.get(f'/messages/{owner}/count', headers=auth)
    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'
    assert set(response.json()) == {'pending_count', 'revision'}
    return response.json()


def test_counts_are_non_destructive_and_new_arrival_changes_revision_at_same_count(raw_client):
    sender, owner = user_id('count-sender'), user_id('count-owner')
    auth = credential(raw_client, owner)
    assert count(raw_client, owner, auth) == dict(pending_count=0, revision=0)
    first = send(raw_client, sender, owner, 1)
    initial = count(raw_client, owner, auth)
    assert initial['pending_count'] == 1 and initial['revision'] > 0
    for _ in range(3):
        assert count(raw_client, owner, auth) == initial
    # A duplicate retry is not a new arrival and count GET does not mark received.
    assert raw_client.post('/send', headers=headers(raw_client, sender), json=first).status_code == 201
    assert count(raw_client, owner, auth) == initial
    inbox = raw_client.get(f'/messages/{owner}', headers=headers(raw_client, owner)).json()['messages']
    assert len(inbox) == 1 and inbox[0]['ciphertext'] == 'opaque-contents'
    assert raw_client.get(f'/statuses/{sender}', headers=headers(raw_client, sender)).json()['statuses'][0]['state'] == 'queued'
    assert raw_client.post(f'/messages/{owner}/ack', headers=headers(raw_client, owner), json={'ids': [first['id']]}).status_code == 200
    assert count(raw_client, owner, auth)['pending_count'] == 0
    send(raw_client, sender, owner, 2)
    following = count(raw_client, owner, auth)
    assert following['pending_count'] == 1 and following['revision'] > initial['revision']


def test_scoped_credential_cannot_download_ack_send_renew_or_access_other_owner(raw_client):
    owner, other = user_id('scoped-owner'), user_id('scoped-other')
    auth = credential(raw_client, owner)
    assert raw_client.get(f'/messages/{other}/count', headers=auth).status_code == 403
    for method, path, body in [
        ('GET', f'/messages/{owner}', None), ('GET', f'/statuses/{owner}', None),
        ('POST', f'/messages/{owner}/ack', {'ids': ['a'*32]}),
        ('POST', '/send', dict(sender=owner, recipient=other, ciphertext='opaque')),
        ('POST', '/notifications/token', {}), ('DELETE', '/notifications/token', None),
        ('GET', '/prekeys/status', None),
    ]:
        assert raw_client.request(method, path, headers=auth, json=body).status_code == 401, path
    assert raw_client.get(f'/messages/{owner}/count').status_code == 401
    assert raw_client.request('HEAD', f'/messages/{owner}/count', headers=auth).status_code == 200


def test_rotation_revocation_and_persistence_without_plaintext_token(server_factory, tmp_path):
    directory = tmp_path / 'persistent'
    running = server_factory(MESSAGE_DATA_DIR=str(directory))
    client = HTTPClient(running.port)
    owner, sender = user_id('persist-count'), user_id('persist-sender')
    old = credential(client, owner)
    auth = credential(client, owner)
    assert client.get(f'/messages/{owner}/count', headers=old).status_code == 401
    send(client, sender, owner, 3)
    before = count(client, owner, auth)
    with sqlite3.connect(directory / 'messages.sqlite3') as db:
        stored = db.execute('SELECT token_hash FROM notification_tokens WHERE owner=?', (owner,)).fetchone()[0]
        assert stored == hashlib.sha256(auth['Authorization'][7:].encode()).digest()
        plan = db.execute("EXPLAIN QUERY PLAN SELECT count(*),max(arrival) FROM messages INDEXED BY inbox_counts WHERE recipient=? AND state='queued' AND expires_at>?", (owner, int(time.time()))).fetchall()
        assert any('COVERING INDEX inbox_counts' in row[3] for row in plan)
    running.stop()
    restarted = server_factory(MESSAGE_DATA_DIR=str(directory))
    client = HTTPClient(restarted.port)
    assert count(client, owner, auth) == before
    assert client.post(f'/messages/{owner}/ack', headers=headers(client, owner), json={'ids': [f'{3:032x}']}).status_code == 200
    send(client, sender, owner, 4)
    assert count(client, owner, auth)['revision'] > before['revision']
    assert client.request('DELETE', '/notifications/token', headers=headers(client, owner)).status_code == 200
    assert client.get(f'/messages/{owner}/count', headers=auth).status_code == 401


def test_expired_tokens_and_messages_are_excluded(server_factory):
    running = server_factory(NOTIFICATION_TOKEN_TTL=2, MESSAGE_TTL_SECONDS=2)
    client = HTTPClient(running.port)
    owner, sender = user_id('expiry-count'), user_id('expiry-sender')
    send(client, sender, owner, 5)
    auth = credential(client, owner)
    assert count(client, owner, auth)['pending_count'] == 1
    time.sleep(2.1)
    assert client.get(f'/messages/{owner}/count', headers=auth).status_code == 401
    assert count(client, owner, headers(client, owner))['pending_count'] == 0


def test_scoped_credentials_are_bounded_and_owner_can_rotate_at_capacity(server_factory):
    client = HTTPClient(server_factory(NOTIFICATION_TOKEN_LIMIT=1).port)
    first, second = user_id('cap-count-a'), user_id('cap-count-b')
    credential(client, first)
    credential(client, first)
    assert client.post('/notifications/token', headers=headers(client, second), json={}).status_code == 429


def test_count_endpoint_migrates_legacy_message_database(server_factory, tmp_path):
    directory = tmp_path / 'legacy'
    directory.mkdir()
    owner, sender = user_id('legacy-count'), user_id('legacy-sender')
    with sqlite3.connect(directory / 'messages.sqlite3') as db:
        db.execute('CREATE TABLE messages (id TEXT PRIMARY KEY,sender TEXT NOT NULL,recipient TEXT NOT NULL,ciphertext TEXT,created_at TEXT NOT NULL,expires_at INTEGER NOT NULL,state TEXT NOT NULL)')
        db.execute('INSERT INTO messages VALUES (?,?,?,?,?,?,?)', ('a'*32,sender,owner,'opaque','2026-10-19',int(time.time())+1000,'queued'))
    client = HTTPClient(server_factory(MESSAGE_DATA_DIR=str(directory)).port)
    auth = credential(client, owner)
    assert count(client, owner, auth) == dict(pending_count=1, revision=0)
    send(client, sender, owner, 6)
    assert count(client, owner, auth) == dict(pending_count=2, revision=1)
