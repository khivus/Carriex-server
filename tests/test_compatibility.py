def test_health_advertises_server_version_and_explicit_app_range(client):
    """Use the real unauthenticated localhost health endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["version"] == "0.6.1"
    assert data["compatibility"] == {
        "protocol": 3,
        "min_app_version_code": 10,
        "recommended_app_version_code": 11,
        "max_app_version_code": 12,
    }
