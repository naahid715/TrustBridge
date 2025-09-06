# Cyber Privacy Prototype (Govt + Judge Two-Key Access)

This is a hackathon-ready Flask app that demonstrates a realistic balance between **national security** and **individual privacy** using a **two-key cryptographic unlock**:

- Data is encrypted with a random Fernet (AES) key.
- That key is split into two XOR shares:
  - One share encrypted with the **Judge's RSA public key**
  - One share encrypted with the **Govt's RSA public key**
- To decrypt, both Judge and Govt must cooperate with their **private keys** (2-of-2 scheme).

## Run Locally

```bash
cd cyber_privacy_project
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000/ in your browser.

## Demo Flow

1. **Citizen** uploads private data at `/citizen` → encrypted immediately.
2. **Govt** views metadata and clicks "Request Full Access" at `/govt`.
3. **Judge** reviews and approves the request at `/judge` (this decrypts the judge's key share).
4. **Govt** returns to `/govt` and clicks "Complete Decryption & View" to reveal the message.

All actions are recorded in **Audit Logs** at `/logs`.

> Keys are generated on first run into `./keys/*.pem` for demo purposes only.
> Replace in-memory stores with SQLite if you want persistence beyond a single run.
