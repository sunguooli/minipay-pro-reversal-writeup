# MiniPay 独立客户端：bootstrap -> auth/challenge -> auth/session
# 每个请求一个函数，签名参数显式传递，不共用改来改去的 install_header
import requests, hashlib, hmac, secrets, time, json
import urllib3
urllib3.disable_warnings()

BASE = "https://192.168.56.1:5443"
DEVICE_ID = "968b5de4a3271c18"
INSTALL_ID = "d6b8db808d26b84b95a49535"
ACCOUNT = "admin"
PASSWORD = "123456"

ROOT_REQ = b"MiniPay.Request.Root/v2"      # byte_B00[i&7]^byte_DDA[i], 23B
ROOT_PW  = b"MiniPay.Password.Proof/v2"    # byte_B00[i&7]^byte_DF1[i], 25B

PROXIES = {"https": "http://127.0.0.1:8888"}

def base_headers():
    return {
        'Accept': 'application/json',
        'Content-Type': 'application/json; charset=utf-8',
        'User-Agent': 'MiniPay/4.5.0-lab Android',
        'X-MP-Channel': 'lab-commercial',
        'X-MP-Install': INSTALL_ID,
        'X-MP-Device': DEVICE_ID,
        'X-MP-Risk': '524288',
        'Host': '192.168.56.1:5443',
    }

def make_proof(method, path_with_query, body_bytes, session=""):
    """生成 X-MP-Proof。ts/nonce 生成一次，header 和签名明文共用。"""
    ts = str(int(time.time()))
    nonce = secrets.token_bytes(12).hex()
    body_hex = hashlib.sha256(body_bytes).hexdigest()
    k1 = hmac.new(ROOT_REQ, DEVICE_ID.encode(), hashlib.sha256).digest()
    k2 = hmac.new(k1, b"req-v2\n" + session.encode(), hashlib.sha256).digest()
    plaintext = "MP2\n%s\n%s\n%s\n%s\n%s\n%s\n%08x\n%s" % (
        method, path_with_query, ts, nonce, session, DEVICE_ID, 0x80000, body_hex)
    sig = hmac.new(k2, plaintext.encode(), hashlib.sha256).hexdigest()
    return (f"MP2 kid=lab-k2,ts={ts},nonce={nonce},risk=00080000,"
            f"body={body_hex},sig={sig}", ts, nonce)

def credential_proof(account, password, challenge_field):
    stage1 = hashlib.sha256(
        ROOT_PW + b"\0" + account.encode() + b"\0" + password.encode()).digest()
    msg = "P2\n%s\n%s\n%s" % (account, challenge_field, DEVICE_ID)
    sig = hmac.new(stage1, msg.encode(), hashlib.sha256).hexdigest()
    return "P2." + sig

def show(tag, res):
    print(f"--- {tag}: {res.status_code}")
    print(res.text[:500])

def req_bootstrap():
    path = "/api/v2/bootstrap"
    proof, ts, nonce = make_proof("GET", path, b"")
    h = base_headers()
    h['X-MP-Timestamp'], h['X-MP-Nonce'], h['X-MP-Proof'] = ts, nonce, proof
    return requests.get(BASE + path, headers=h, verify=False, proxies=PROXIES)

def req_challenge():
    query = f"account={ACCOUNT}&device_id={DEVICE_ID}"
    path = "/api/v2/auth/challenge"
    proof, ts, nonce = make_proof("GET", path + "?" + query, b"")
    h = base_headers()
    h['X-MP-Timestamp'], h['X-MP-Nonce'], h['X-MP-Proof'] = ts, nonce, proof
    return requests.get(BASE + path + "?" + query, headers=h, verify=False, proxies=PROXIES)

def req_session(challenge, challenge_id):
    path = "/api/v2/auth/session"
    data = {
        'account': ACCOUNT,
        'challenge': challenge,
        'challenge_id': challenge_id,
        'credential_proof': credential_proof(ACCOUNT, PASSWORD, challenge),
        'device_id': DEVICE_ID,
        'install_id': INSTALL_ID,
    }
    body = json.dumps(data, separators=(",", ":")).encode()
    proof, ts, nonce = make_proof("POST", path, body)
    h = base_headers()
    h['X-MP-Timestamp'], h['X-MP-Nonce'], h['X-MP-Proof'] = ts, nonce, proof
    print("credential_proof =", data['credential_proof'])
    return requests.post(BASE + path, headers=h, data=body, verify=False, proxies=PROXIES)

if __name__ == "__main__":
    r1 = req_bootstrap()
    show("bootstrap", r1)
    r2 = req_challenge()
    show("challenge", r2)
    j = r2.json()
    r3 = req_session(j['challenge'], j['challenge_id'])
    show("session", r3)
