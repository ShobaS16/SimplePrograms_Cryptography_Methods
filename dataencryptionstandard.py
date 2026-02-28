from flask import Flask, request, render_template_string

app = Flask(__name__)

# ---------------- BASIC FUNCTIONS ----------------
def permute(bits, table):
    return ''.join(bits[i-1] for i in table)

def left_shift(bits, n):
    return bits[n:] + bits[:n]

def xor(a, b):
    out = ""
    for i in range(len(a)):
        out += '0' if a[i] == b[i] else '1'
    return out

# ---------------- S-BOXES ----------------
S0 = [
    [1,0,3,2],
    [3,2,1,0],
    [0,2,1,3],
    [3,1,3,2]
]

S1 = [
    [0,1,2,3],
    [2,0,1,3],
    [3,0,1,0],
    [2,1,0,3]
]

def sbox(bits, box, name, log):
    row = int(bits[0] + bits[3], 2)
    col = int(bits[1] + bits[2], 2)
    log.append(f"{name}: Row = {bits[0]}{bits[3]} = {row}, "
               f"Column = {bits[1]}{bits[2]} = {col}")
    val = box[row][col]
    out = format(val, "02b")
    log.append(f"{name} Output = {val} → {out}")
    return out

# ---------------- HTML ----------------
HTML = """
<!DOCTYPE html>
<html>
<head>
<title>S-DES Manual Notes Style</title>
<style>
body { font-family: Times New Roman; background:#eef2ff; }
.container { width:1000px; margin:auto; background:white; padding:20px; }
input, button { width:100%; padding:6px; margin:4px 0; }
pre { background:#f1f5f9; padding:15px; font-size:16px; }
button { background:#1e3a8a; color:white; border:none; }
</style>
</head>
<body>
<div class="container">
<h2 align="center">S-DES (User-Defined Tables, Full Intermediate Steps)</h2>

<form method="post">
Plaintext (8-bit): <input name="pt">
Ciphertext (for Decryption): <input name="ct">
Key (10-bit): <input name="key">

P10: <input name="p10">
P8: <input name="p8">
IP: <input name="ip">
IP-1: <input name="ip1">
EP: <input name="ep">
P4: <input name="p4">

<button name="action" value="enc">ENCRYPT</button>
<button name="action" value="dec">DECRYPT</button>
</form>

{% if out %}
<h3>Step-by-Step Output</h3>
<pre>{{ out }}</pre>
{% endif %}
</div>
</body>
</html>
"""

# ---------------- CORE LOGIC ----------------
def sdes_process(text, key, tables, encrypt=True):
    log = []

    P10, P8, IP, IP1, EP, P4 = tables

    # ----- KEY GENERATION -----
    log.append("KEY GENERATION\n")

    p10 = permute(key, P10)
    log.append(f"P10(Key) = {p10}")

    L, R = p10[:5], p10[5:]
    log.append(f"Split → L={L}, R={R}")

    L1 = left_shift(L, 1)
    R1 = left_shift(R, 1)
    log.append(f"LS-1 → L={L1}, R={R1}")

    K1 = permute(L1 + R1, P8)
    log.append(f"K1 = P8(L||R) = {K1}")

    L2 = left_shift(L1, 2)
    R2 = left_shift(R1, 2)
    log.append(f"LS-2 → L={L2}, R={R2}")

    K2 = permute(L2 + R2, P8)
    log.append(f"K2 = P8(L||R) = {K2}")

    if not encrypt:
        K1, K2 = K2, K1
        log.append("\nKeys reversed for Decryption")

    # ----- INITIAL PERMUTATION -----
    log.append("\nINITIAL PERMUTATION")
    ip = permute(text, IP)
    log.append(f"IP(Text) = {ip}")

    L0, R0 = ip[:4], ip[4:]
    log.append(f"L0={L0}, R0={R0}")

    # ----- ROUND 1 -----
    log.append("\nROUND 1")
    ep = permute(R0, EP)
    log.append(f"EP(R0) = {ep}")

    x1 = xor(ep, K1)
    log.append(f"EP ⊕ K = {x1}")

    s0 = sbox(x1[:4], S0, "S0", log)
    s1 = sbox(x1[4:], S1, "S1", log)

    p4 = permute(s0 + s1, P4)
    log.append(f"P4 = {p4}")

    L1 = xor(L0, p4)
    log.append(f"L1 = L0 ⊕ P4 = {L1}")

    log.append(f"SWAP → L={R0}, R={L1}")

    # ----- ROUND 2 -----
    log.append("\nROUND 2")
    ep2 = permute(L1, EP)
    log.append(f"EP(R1) = {ep2}")

    x2 = xor(ep2, K2)
    log.append(f"EP ⊕ K = {x2}")

    s0 = sbox(x2[:4], S0, "S0", log)
    s1 = sbox(x2[4:], S1, "S1", log)

    p4 = permute(s0 + s1, P4)
    log.append(f"P4 = {p4}")

    L2 = xor(R0, p4)
    log.append(f"L2 = L ⊕ P4 = {L2}")

    final = permute(L2 + L1, IP1)
    log.append(f"\nFinal Output = IP-1(L||R) = {final}")

    return "\n".join(log)

# ---------------- ROUTE ----------------
@app.route("/", methods=["GET","POST"])
def index():
    out = None
    if request.method == "POST":
        tables = [
            list(map(int, request.form["p10"].split())),
            list(map(int, request.form["p8"].split())),
            list(map(int, request.form["ip"].split())),
            list(map(int, request.form["ip1"].split())),
            list(map(int, request.form["ep"].split())),
            list(map(int, request.form["p4"].split()))
        ]

        if request.form["action"] == "enc":
            out = sdes_process(request.form["pt"], request.form["key"], tables, True)
        else:
            out = sdes_process(request.form["ct"], request.form["key"], tables, False)

    return render_template_string(HTML, out=out)

if __name__ == "__main__":
    app.run(debug=True)
