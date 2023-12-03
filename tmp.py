import random
import re
import time
from urllib.parse import quote_plus
import uuid
from trycourier import Courier
from bson import Binary
import streamlit as st
from streamlit_option_menu import option_menu
from pydantic import validate_email
import configparser
import redis
import pymongo
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import base64



st.set_page_config(
        page_title="SafeSSH",
        page_icon="key",
        layout="wide",
    )

# Load credentials from the config file
#config = configparser.ConfigParser()
#config.read("config.ini")



#STREAMLIT CONFIG CODE
# Everything is accessible via the st.secrets dict:
#st.write("DB username:", st.secrets["db_username"])
#st.write("DB password:", st.secrets["db_password"])
#st.write("My cool secrets:", st.secrets["my_cool_secrets"]["things_i_like"])

# And the root-level secrets are also accessible as environment variables:
#st.write(
#    "Has environment variables been set:",
#    os.environ["db_username"] == st.secrets["db_username"],)

#REDIS_HOST = config.get("redis", "host")
#REDIS_HOST =config["redis"]["host"]
#REDIS_PORT = config.getint("redis", "port")
#REDIS_PASSWORD = config.get("redis", "password")
#'''
REDIS_HOST = st.secrets["redis"]["host"]
REDIS_PORT = st.secrets["redis"]["port"]
REDIS_PASSWORD = st.secrets["redis"]["password"]

# Connect to Redis
redis_client = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True)

# MongoDB connection details
#MONGO_URI = config.get("mongodb", "uri")
#MONGO_DB = config.get("mongodb", "db_name")

MONGO_URI = st.secrets["mongodb"]["uri"]
MONGO_DB = st.secrets["mongodb"]["db_name"]

# Connect to MongoDB
mongo_client = pymongo.MongoClient(MONGO_URI)
db = mongo_client[MONGO_DB]


#EmailCourier  
#auth_token = config.get("mail","auth_token")
#sendermail = config.get("mail","email")

auth_token = st.secrets["mail"]["auth_token"]
sendermail = st.secrets["mail"]["email"]

client = Courier(auth_token=auth_token)




def is_username_unique(username):
    # Check if the username already exists in Redis
    return redis_client.hget("users", username) is None

def is_valid_email(email):
    # Validate the email format
    return validate_email(email)
# Function to check if the user is logged in
def is_user_logged_in():
    return "username" in st.session_state


# Function to log out the user
def logout():
    if is_user_logged_in():
        del st.session_state["username"]
        st.success("Logged out successfully")

# Function to display the main menu for logged-in users
def display_main_menu():

    # Add your main menu options here
    main_menu_option = option_menu("Main Menu", ["Add","Download", "Generate", "Delete","Rename", "Reset Password"],
                                icons=['file-earmark-plus', 'cloud-arrow-down','pc','trash','recycle','file-lock2'],
                                    menu_icon="gear", default_index=0, orientation="horizontal")
    main_menu_option
    
    #if main_menu_option == "Logout":
       # logout()
    
        # Handle other menu options here
    if main_menu_option == "Add":
        add_keys()

    elif main_menu_option == "Download":
        download_keys()
    elif main_menu_option == "Generate":
        st.title("Generate your SSH key pair here.")
        # Two equal columns:
        col1, col2 = st.columns(2)
        if col1.button("Generate SSH Key Pair"):
            generate_and_save_ssh_key_pair()

        if col2.button("Generate & Store"):
            generate_and_save_ssh()
    elif main_menu_option=="Rename":
        rename_server()

    elif main_menu_option == "Delete":
        delete_keys() 
    elif main_menu_option == "Reset Password":
       st.title("Reset Password")

# Function to delete keys
def generate_and_save_ssh_key_pair():
    # Generate a new RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Get the public key in OpenSSH format
    public_key = private_key.public_key()
    ssh_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode("utf-8")

    # Get the private key in PEM format
    ssh_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    # Display the keys in the Streamlit app
    #st.text("SSH Private Key:")
    #st.text(ssh_private_key)

    #st.text("SSH Public Key:")
    #st.text(ssh_public_key)

    # Provide download links for the keys with the desired filenames
    st.markdown(get_download_link(ssh_private_key, "id_rsa", "Download Private Key"), unsafe_allow_html=True)
    st.markdown(get_download_link(ssh_public_key, "id_rsa.pub", "Download Public Key"), unsafe_allow_html=True)

    st.success("Keys Generated!")

def get_download_link(content, filename, link_text):
    """Generate a download link for a given content and filename."""
    content = content.encode("utf-8")
    b64 = base64.b64encode(content).decode()
    href = f'<a href="data:application/octet-stream;base64,{b64}" download="{filename}">{link_text}</a>'
    return href

    st.success("keys Generated and saved to your system!")


def generate_and_save_ssh():
    st.title("Generate and Save SSH Key Pair")

    # Get username from session state
    username = st.session_state["username"]
    digits = max(1, min(6, 10))  # Limiting to 10 digits for simplicity

    # Generate a random integer with 'digits' digits
    unique_code = str(random.randint(10 ** (digits - 1), 10 ** digits - 1))
    # Ask for server name
    server_name = unique_code
# Generate key and UUID once at the beginning
    key, record_id = generate_key_and_uuid()

        # Generate a new RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
            backend=default_backend()
        )

        # Get the public key in OpenSSH format
    public_key = private_key.public_key()
    ssh_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode("utf-8")

        # Get the private key in PEM format
    ssh_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

        # Encrypt both private and public key content using the generated key
    encrypted_private_key = Fernet(key).encrypt(ssh_private_key.encode("utf-8"))
    encrypted_public_key = Fernet(key).encrypt(ssh_public_key.encode("utf-8"))

    st.success("SSH keys generated and saved successfully!")

        # Save the keys to files
    with open(f'{server_name}_{record_id}_private_key.pem', 'wb') as private_key_file:
        private_key_file.write(ssh_private_key.encode("utf-8"))

    with open(f'{server_name}_{record_id}_public_key.pub', 'wb') as public_key_file:
        public_key_file.write(ssh_public_key.encode("utf-8"))

    with open(f'{server_name}_{record_id}_private_key_encrypted.txt', 'wb') as encrypted_private_file:
        encrypted_private_file.write(encrypted_private_key)

    with open(f'{server_name}_{record_id}_public_key_encrypted.txt', 'wb') as encrypted_public_file:
        encrypted_public_file.write(encrypted_public_key)

    # Store the encrypted keys in the user's MongoDB collection under the specified server name
    collection = db[username]
    collection.insert_one({
            "record_id": record_id,
            "server_name": server_name,
            "publickey": Binary(encrypted_public_key),
            "privatekey": Binary(encrypted_private_key),
            "encryption_key": key  # Store the key in the collection
        })

        # Return the generated key and record ID
    st.info(f"Server Name: {server_name}")
    st.info(f"Encryption Key: {key}", icon="ℹ️")
    st.info(f"UID: {record_id}", icon="ℹ️")

def rename_server():
    st.title("Rename Server")

    if not is_user_logged_in():
        st.error("You need to be logged in to access this functionality.")
        return

    # Get username from session state
    username = st.session_state["username"]

    # Ask for existing server name
    existing_server_name = st.text_input("Enter existing server name:")
    if not existing_server_name:
        st.warning("Please enter the existing server name.")
        return

    # Check if the existing server name exists in the user's MongoDB collection
    collection = db[username]
    existing_server = collection.find_one({"server_name": existing_server_name})

    if existing_server:
        st.success(f"Server '{existing_server_name}' found!")

        # Ask for the new server name
        new_server_name = st.text_input("Enter new server name:")
        if not new_server_name:
            st.warning("Please enter the new server name.")
            return

        # Update the server name in the MongoDB collection
        collection.update_one(
            {"server_name": existing_server_name},
            {"$set": {"server_name": new_server_name}}
        )

        st.success(f"Server '{existing_server_name}' renamed to '{new_server_name}' successfully!")
    else:
        st.warning(f"Server '{existing_server_name}' not found.")

# You can call this function in your main application where appropriate.
# Example: If you have a "Rename Server" button, you can connect it to this function.




# Function to delete keys
def delete_keys():
    st.title("Delete Keys")

    if not is_user_logged_in():
        st.error("You need to be logged in to access this functionality.")
        return

    # Get username from session state
    username = st.session_state["username"]

    # Retrieve all keys from the user's MongoDB collection
    collection = db[username]
    user_keys = list(collection.find({}, {"_id": 0, "server_name": 1, "publickey": 1, "privatekey": 1, "encryption_key": 1}))

    if user_keys:
        # Display keys and add a delete button for each pair
        for i, keys in enumerate(user_keys):
            st.subheader(f"{keys['server_name']}:")
            st.code(f"Public Key: {keys['publickey']}")
            st.code(f"Private Key: {keys['privatekey']}")
            st.code(f"Encryption Key: {keys['encryption_key']}")
            # Add a delete button for each key pair with a unique key
            delete_button_key = f"delete_button_{i}"
            if st.button(f"Delete Keys for {keys['server_name']}", key=delete_button_key):
                # Delete the entire key pair from MongoDB collection
                collection.delete_one(keys)

                st.success(f"Keys Set {keys['server_name']} deleted successfully!")
    else:
        st.warning("No keys found for the user.")


# Function to generate key and UUID
def generate_key_and_uuid():
    # Generate a random ID for the record
    record_id = str(uuid.uuid4())

    # Generate a key for encryption
    key = Fernet.generate_key()

    return key, record_id

# Modified add_keys function
def add_keys():
    st.title("Add Keys")

    # Get username from session state
    username = st.session_state["username"]

    # Ask for server name
    server_name = st.text_input("Enter server name:")

    # Generate key and UUID once at the beginning
    key, record_id = generate_key_and_uuid()

    # File upload for private key
    private_key_file = st.file_uploader("Upload Private Key (id_rsa)")
    public_key_file = st.file_uploader("Upload Public Key (.pub)", type=["pub", "txt"])

    # Check if both files are uploaded and server name is provided
    if private_key_file and public_key_file and server_name:
        # Read the contents of the files
        private_key_content = private_key_file.read()
        public_key_content = public_key_file.read()

        # Encrypt the private and public key content using the same key
        encrypted_private_key = Fernet(key).encrypt(private_key_content)
        encrypted_public_key = Fernet(key).encrypt(public_key_content)

        st.success("Keys added successfully!")

        # Save the keys to files
        with open(f'{username}_{server_name}_{record_id}_private_key.key', 'wb') as filekey:
            filekey.write(key)

        with open(f'{username}_{server_name}_{record_id}_private_key_encrypted.txt', 'wb') as encrypted_file:
            encrypted_file.write(encrypted_private_key)

        with open(f'{username}_{server_name}_{record_id}_public_key.key', 'wb') as filekey:
            filekey.write(key)

        with open(f'{username}_{server_name}_{record_id}_public_key_encrypted.txt', 'wb') as encrypted_file:
            encrypted_file.write(encrypted_public_key)

        # Store the encrypted keys in the user's MongoDB collection under the specified server name
        collection = db[username]
        collection.insert_one({
            "record_id": record_id,
            "server_name": server_name,
            "publickey": Binary(encrypted_public_key),
            "privatekey": Binary(encrypted_private_key),
            "encryption_key": key  # Store the key in the collection
        })


        # Return the generated key and record ID
        st.info(f"Encryption Key: {key}", icon="ℹ️")
        st.info(f"UID: {record_id}", icon="ℹ️")
        return key, record_id
        

    else:
        st.warning("Please upload both private and public keys, and provide a server name.")
        return None


# Function to retrieve or generate a key for a user
def retrieve_or_generate_key(username):
    # Check if the user already has a key in MongoDB
    collection = db[username]
    existing_key_document = collection.find_one({}, {"_id": 0, "key": 1})

    if existing_key_document and "key" in existing_key_document:
        # Retrieve and return the existing key
        return existing_key_document["key"]
    else:
        # Generate a new key and store it in MongoDB
        new_key = Fernet.generate_key()
        collection.update_one({}, {"$set": {"key": new_key}}, upsert=True)
        return new_key

# Function to download keys
def download_keys():
    st.title("Download Keys")

    if not is_user_logged_in():
        st.error("You need to be logged in to access this functionality.")
        return

    # Get username from session state
    username = st.session_state["username"]

    st.info('Enter the Encryption Key below!', icon="ℹ️")

    # Retrieve the key for the user
    key = st.text_input("Enter your key:", type="password")

    # Retrieve keys from the user's MongoDB collection
    collection = db[username]
    user_keys = collection.find_one({}, {"_id": 0, "publickey": 1, "privatekey": 1})

    if user_keys:
        # Decrypt keys with progress bar
        progress_bar = st.progress(0)
        decrypted_public_key = Fernet(key).decrypt(user_keys["publickey"]).decode("utf-8")
        progress_bar.progress(50)
        decrypted_private_key = Fernet(key).decrypt(user_keys["privatekey"]).decode("utf-8")
        progress_bar.progress(100)

        # Save keys to files
        with open(f'private_key', 'w') as private_key_file:
            private_key_file.write(decrypted_private_key)

        with open(f'public_key.pub', 'w') as public_key_file:
            public_key_file.write(decrypted_public_key)

        # Provide download links for the keys
        st.markdown(get_download_link(decrypted_private_key, "id_rsa", "Download Private Key"))
        st.markdown(get_download_link(decrypted_public_key, "id_rsa.pub", "Download Public Key"))

        st.success("Keys decrypted successfully!")

    else:
        st.warning("No keys found for the user.")

def get_download_link(content, filename, link_text):
    """Generate a download link for a given content and filename."""
    content = content.encode("utf-8")
    b64 = base64.b64encode(content).decode()
    href = f'<a href="data:application/octet-stream;base64,{b64}" download="{filename}">{link_text}</a>'
    return href

# Function to retrieve the password based on username and email
def get_password(username, email):
    # Retrieve user data from Redis based on the username
    user_data_str = redis_client.hget("users", username)
    
    if user_data_str:
        user_data = eval(user_data_str)  # Convert the string back to a dictionary

        # Check if the provided email matches the stored email
        if user_data.get("email") == email:
            return user_data.get("password")

    return None

def get_username(email):
    # Iterate through all users in Redis and find the matching email
    for username, user_data_str in redis_client.hgetall("users").items():
        user_data = eval(user_data_str)  # Convert the string back to a dictionary
        if user_data.get("email") == email:
            return username

    return None

# Check if the user is logged in
if is_user_logged_in():
    # Display the main menu for logged-in users
    st.title(f"Welcome, {st.session_state['username']}!")
    display_main_menu()

else:
    # Display the login or create account page based on the selected option
    with st.sidebar:
        authentication = option_menu("Authentication", ["Login", 'Create Account','Forgot Username','Forgot Password'], 
            icons=['door-open', 'person-plus-fill','person-fill-exclamation','person-x'], menu_icon="person-circle", default_index=0)
    st.markdown("<h1 style='text-align: center; color: white;'>SafeSSH</h1>", unsafe_allow_html=True)
    
    if authentication == "Login":
        st.info("Secured Storage 🔐")
        st.info("Anytime Accessibility 🌐")
        st.info("Trustworthy and Reliable 🛡️💼")
        st.info("User-Friendly Interface 🤝")
        # Your login logic here
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            # Check if username exists
            if redis_client.hexists("users", username):
                # Retrieve stored user data
                stored_data_str = redis_client.hget("users", username)
                stored_data_dict = eval(stored_data_str)  # Convert the string back to a dictionary

                # Check if the entered password matches the stored password
                if stored_data_dict["password"] == password:
                    st.session_state["username"] = username  # Store username in session state
                    st.success(f"Welcome, {username}!")
                    display_main_menu()
                else:
                    st.error("Invalid password. Please try again.")
            else:
                st.error("Username not found. Please check your username or create a new account.")
    
    elif authentication == "Create Account":
        st.title("Create Account")

        # Input fields
        name = st.text_input("Name")
        email = st.text_input("Email")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        # Create Account button
        if st.button("Create Account"):
            # Validate email format, check for unique username, and ensure password length
            if re.match(r"[^@]+@[^@]+\.[^@]+", email):
                if is_username_unique(username):
                    if len(password) >= 8:
                        # Store user information in Redis
                        user_data = {"name": name, "email": email, "username": username, "password": password}
                        redis_client.hset("users", username, str(user_data))
                        st.success(f"Account created for {username}!")
                        st.balloons()
                    else:
                        st.error("Password must be 8 characters or more.")
                else:
                    st.error("Username already exists. Please choose a different username.")
            else:
                st.error("Please enter a valid email address.")

    elif authentication=="Forgot Password":
        username = st.text_input("Enter your username:")
        email = st.text_input("Enter your registered email:")

        if st.button("Show Password"):
            # Retrieve the password based on username and email
            password = get_password(username, email)

            if password:
                #st.success(f"Your password is: {password}")
                resp = client.send_message(
                message={
                "to": {
                 "email": sendermail
                },
                "content": {
                 "title": "Forgot Password Request",
                 "body": " {{password}}"
                },
                "data":{
                "password": f"keep your account secure, change password and dont share! password is {password}"
                }
                }
                )

            else:
                st.error("Invalid username or email. Please check your information.")
    
    elif authentication=="Forgot Username":
        email = st.text_input("Enter your registered email:")

        if st.button("Retrieve Username"):
            # Retrieve the username based on the provided email
            username = get_username(email)

            if username:
               st.success(f"Your username has been sent to {email}. Check your email.")
               st.success(username)
            else:
                st.error("No account found with the provided email. Please check your information.")




# Always display the logout button
if is_user_logged_in():
    st.sidebar.button("Logout", on_click=logout)




import os
from datetime import datetime, timedelta
import time
from apscheduler.schedulers.background import BackgroundScheduler

def delete_files_except():
    # Specify folder path
    folder_path = "C:/Users/HP.KHUSHALSARODE.000/Desktop/sshm/"

    # Specify folders and files to exclude from deletion
    exclude_folders = ["temp", "venv"]
    exclude_files = ["config.ini", "requirements.txt", "tmp.py",".gitignore"]

    # Get all files in the folder
    all_files = []
    for root, dirs, files in os.walk(folder_path):
        # Exclude specified folders
        dirs[:] = [d for d in dirs if d not in exclude_folders]
        # Exclude specified files
        files[:] = [f for f in files if f not in exclude_files]
        # Append remaining files to the list
        all_files.extend([os.path.join(root, file) for file in files])

    # Calculate the date threshold for files to be deleted (e.g., files older than 7 days)
    threshold_date = datetime.now() - timedelta(days=1)

    # Iterate through files and delete those that are older than the threshold
    for file_path in all_files:
        # Get the file creation time
        creation_time = datetime.fromtimestamp(os.path.getctime(file_path))

        # Check if the file is older than the threshold
        if creation_time < threshold_date:
            try:
                # Delete the file
                os.remove(file_path)
                print(f"Deleted file: {file_path}")
            except Exception as e:
                print(f"Error deleting file {file_path}: {e}")

# Schedule the cleanup function to run periodically (e.g., daily)
scheduler = BackgroundScheduler()
scheduler.add_job(delete_files_except, 'interval', days=1)  # Adjust the schedule as needed
scheduler.start()

