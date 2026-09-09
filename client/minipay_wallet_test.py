# 实验：登录后带 session 打 GET /api/v2/wallet/summary，验证 Authorization 形态
from minipay_login import (BASE, base_headers, make_proof,
                           req_challenge, req_session, show, PROXIES)
import requests

def req_wallet(session_id, auth_header=None):
    path = "/api/v2/wallet/summary"
    proof, ts, nonce = make_proof("GET", path, b"", session=session_id)
    h = base_headers()
    h['X-MP-Timestamp'], h['X-MP-Nonce'], h['X-MP-Proof'] = ts, nonce, proof
    if auth_header:
        h['Authorization'] = auth_header
    return requests.get(BASE + path, headers=h, verify=False, proxies=PROXIES)

if __name__ == "__main__":
    j = req_challenge().json()
    login = req_session(j['challenge'], j['challenge_id']).json()
    token, sid = login['access_token'], login['session_id']
    print("token =", token, "\nsession_id =", sid)

    show("A: Bearer + sig带session", req_wallet(sid, f"Bearer {token}"))
    show("B: 裸token + sig带session", req_wallet(sid, token))
    show("C: 无Authorization + sig带session", req_wallet(sid))
    show("D: Bearer + sig不带session", req_wallet("", f"Bearer {token}"))
