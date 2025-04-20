import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet

# ------------------ Constants ------------------
DATA_FILE = "data.json"
LOCKOUT_TIME = 30  # seconds
MAX_ATTEMPTS = 3

# ------------------ Helper Functions ------------------
def load_data():
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, "w") as f:
            json.dump({}, f)
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return salt.hex(), key.hex()

def verify_password(stored_salt, stored_key, input_password):
    salt = bytes.fromhex(stored_salt)
    new_key = hashlib.pbkdf2_hmac("sha256", input_password.encode(), salt, 100000)
    return new_key.hex() == stored_key

def get_cipher():
    return Fernet(Fernet.generate_key())

# ------------------ Session Setup ------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.failed_attempts = 0
    st.session_state.lockout_time = 0
    st.session_state.cipher = None

data = load_data()

# ------------------ Pages ------------------
def signup_page():
    st.subheader("📝 Sign Up")
    username = st.text_input("Choose a username")
    password = st.text_input("Choose a password", type="password")
    if st.button("Sign Up"):
        if username in data:
            st.error("❌ Username already exists!")
        else:
            salt, hashed = hash_password(password)
            data[username] = {
                "salt": salt,
                "password": hashed,
                "data": "",
                "passkey": ""
            }
            save_data(data)
            st.success("✅ Account created! Please log in.")

def login_page():
    st.subheader("🔐 Log In")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
        if time.time() - st.session_state.lockout_time < LOCKOUT_TIME:
            st.warning(f"⏳ Too many attempts. Wait {LOCKOUT_TIME} seconds.")
            return
        else:
            st.session_state.failed_attempts = 0

    if st.button("Log In"):
        if username in data and verify_password(data[username]["salt"], data[username]["password"], password):
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.cipher = get_cipher()
            st.success("✅ Logged in successfully!")
            st.rerun()  # 👈 Automatically go to dashboard
        else:
            st.session_state.failed_attempts += 1
            st.session_state.lockout_time = time.time()
            st.error(f"❌ Invalid credentials! Attempts left: {MAX_ATTEMPTS - st.session_state.failed_attempts}")

def dashboard():
    st.subheader(f"Welcome, {st.session_state.username} 👋")

    menu = st.radio("Menu", ["Store Data", "Retrieve Data", "Logout"])

    if menu == "Store Data":
        text = st.text_area("Enter text to encrypt:")
        passkey = st.text_input("Set a passkey for this data:", type="password")
        if st.button("Encrypt & Save"):
            if text and passkey:
                cipher = st.session_state.cipher
                encrypted_text = cipher.encrypt(text.encode()).decode()
                hashed_passkey = hashlib.sha256(passkey.encode()).hexdigest()

                data[st.session_state.username]["data"] = encrypted_text
                data[st.session_state.username]["passkey"] = hashed_passkey
                save_data(data)
                st.success("✅ Data encrypted and saved.")
            else:
                st.error("⚠️ Please fill all fields.")

    elif menu == "Retrieve Data":
        passkey = st.text_input("Enter your passkey to decrypt data:", type="password")
        if st.button("Decrypt"):
            encrypted_text = data[st.session_state.username]["data"]
            stored_passkey = data[st.session_state.username]["passkey"]
            hashed_input = hashlib.sha256(passkey.encode()).hexdigest()

            if hashed_input == stored_passkey:
                try:
                    decrypted = st.session_state.cipher.decrypt(encrypted_text.encode()).decode()
                    st.success(f"🔓 Decrypted Data: {decrypted}")
                    st.session_state.failed_attempts = 0
                except:
                    st.error("⚠️ Cipher mismatch. Please logout and login again.")
            else:
                st.session_state.failed_attempts += 1
                remaining = MAX_ATTEMPTS - st.session_state.failed_attempts
                st.error(f"❌ Wrong passkey! Attempts left: {remaining}")
                if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                    st.warning("🔒 Too many attempts. Redirecting to login...")
                    st.session_state.logged_in = False
                    st.session_state.username = ""
                    st.session_state.cipher = None
                    st.session_state.lockout_time = time.time()
                    st.rerun()

    elif menu == "Logout":
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.cipher = None
        st.success("👋 Logged out successfully.")
        st.rerun()

# ------------------ Main App ------------------
st.title("🔐 Secure Data Encryption System")

if not st.session_state.logged_in:
    choice = st.sidebar.radio("Navigation", ["Login", "Sign Up"])
    if choice == "Login":
        login_page()
    else:
        signup_page()
else:
    dashboard()
