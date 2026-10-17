import secrets, string

def generate(length=16, include_symbols=True):
    pool = string.ascii_letters + string.digits
    if include_symbols: pool += "!@#$%^&*()-_=+"
    while True:
        pw = "".join(secrets.choice(pool) for _ in range(length))
        if any(c.isupper() for c in pw) and any(c.islower() for c in pw) and any(c.isdigit() for c in pw):
            return pw