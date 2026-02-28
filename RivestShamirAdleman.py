from flask import Flask, request
import math
import random

app = Flask(__name__)

# ================= BASIC MATH ================= #

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    for d in range(1, phi):
        if (e * d) % phi == 1:
            return d
    return None

# ================= RSA KEY GENERATION ================= #

def generate_keys(p, q, log):
    log.append("=== KEY GENERATION ===")
    n = p * q
    log.append(f"n = p * q = {p} * {q} = {n}")

    phi = (p - 1) * (q - 1)
    log.append(f"phi(n) = (p-1)*(q-1) = {phi}")

    # choose e
    e = 2
    while e < phi:
        if gcd(e, phi) == 1:
            break
        e += 1

    log.append(f"Chosen e = {e}")

    d = mod_inverse(e, phi)
    log.append(f"Computed d (mod inverse of e) = {d}")

    log.append(f"Public Key = ({e}, {n})")
    log.append(f"Private Key = ({d}, {n})\n")

    return e, d, n

# ================= RSA ENCRYPT ================= #

def rsa_encrypt(message, p, q):
    log = []
    e, d, n = generate_keys(p, q, log)

    log.append("=== ENCRYPTION ===")
    cipher = []

    for char in message:
        m = ord(char)
        c = pow(m, e, n)
        cipher.append(c)
        log.append(f"{char} -> {m}^{e} mod {n} = {c}")

    log.append("\nCiphertext:")
    log.append(' '.join(map(str, cipher)))

    return '\n'.join(log)

# ================= RSA DECRYPT ================= #

def rsa_decrypt(ciphertext, p, q):
    log = []
    e, d, n = generate_keys(p, q, log)

    log.append("=== DECRYPTION ===")
    cipher_numbers = list(map(int, ciphertext.split()))
    message = ""

    for c in cipher_numbers:
        m = pow(c, d, n)
        message += chr(m)
        log.append(f"{c}^{d} mod {n} = {m} -> {chr(m)}")

    log.append("\nRecovered Plaintext:")
    log.append(message)

    return '\n'.join(log)

# ================= ROUTES ================= #

@app.route("/", methods=["GET"])
def home():
    return """
    <h2>RSA Algorithm (Notes Style)</h2>
    <form method="post" action="/process">
    Enter Prime p:<br>
    <input name="p"><br><br>
    Enter Prime q:<br>
    <input name="q"><br><br>
    Message / Ciphertext:<br>
    <input name="text" size="40"><br><br>

    <button name="action" value="encrypt">Encrypt</button>
    <button name="action" value="decrypt">Decrypt</button>
    </form>
    """

@app.route("/process", methods=["POST"])
def process():
    p = int(request.form["p"])
    q = int(request.form["q"])
    text = request.form["text"]
    action = request.form["action"]

    if action == "encrypt":
        result = rsa_encrypt(text, p, q)
        return f"<h2>Encryption Output</h2><pre>{result}</pre>"
    else:
        result = rsa_decrypt(text, p, q)
        return f"<h2>Decryption Output</h2><pre>{result}</pre>"

if __name__ == "__main__":
    app.run(debug=True)