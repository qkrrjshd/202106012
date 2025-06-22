import os, pytest, json, requests

API = os.getenv("API_URL", "http://127.0.0.1:8000")

@pytest.fixture(scope="session")
def token():
    res = requests.post(f"{API}/token",
                        data={"username": "test@test.com", "password": "testpw"})
    return res.json()["access_token"]

def test_predict_ddos(token):
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "features": [123456, 15, 10],
        "src_ip": "8.8.8.8",
        "dst_port": 80
    }
    res = requests.post(f"{API}/predict/ddos", headers=headers, json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "risk_score" in data
