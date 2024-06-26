import os
import pickle
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
import logging
from dotenv import load_dotenv
from app.models.vendors import GoogleEntity, MicrosoftEntity, VendorEntity
from redis import StrictRedis
import sqlite3


load_dotenv()
basedir     = os.path.abspath(os.path.dirname(__file__))
log_path    = os.path.join(basedir, 'app.log')
client_id   = os.environ["AZURE_MID_CLIENT_ID"]

log_lvl = logging.getLevelName(os.environ.get("LOG_LEVEL"))

# Setup logging
logging.basicConfig(filename=log_path, level=log_lvl, format='%(asctime)s [[%(name)s]] %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


""" Get all environment variables required for the application."""
# Get the secrets names fot eh Key VaultSetup the Azure Speech Service Key and Region
client_id                       = os.environ['AZURE_MID_CLIENT_ID']
key_vault_name                  = os.environ["AZURE_KEY_VAULT_NAME"]

""" Setup access to the Key Vault."""
key_vault_uri   = f"https://{key_vault_name}.vault.azure.net"
credential      = DefaultAzureCredential(managed_identity_client_id=client_id)
client          = SecretClient(vault_url=key_vault_uri, credential=credential)

# Redis Cache
redis_host_name_secret_name = os.environ["REDIS_HOSTNAME_SECRET_NAME"]
redis_key_secret_name = os.environ["REDIS_PASSWORD_SECRET_NAME"]
myHostname = client.get_secret(redis_host_name_secret_name).value
myPassword = client.get_secret(redis_key_secret_name).value

""" Setup the Redis Cache Connection."""
redis_connection = StrictRedis(host=myHostname, port=6380, password=myPassword, ssl=True)


class DataLoader():
    def __init__(self):
        self.conn = sqlite3.connect('vendors.db')
        self.cursor = self.conn.cursor() 

    def create_tables(self):
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS VendorEntity (
            vendor_id TEXT UNIQUE,
            vendor_name TEXT
        )''')

        self.cursor.execute('''CREATE TABLE IF NOT EXISTS MicrosoftEntity (
            vendor_id TEXT UNIQUE,
            vendor_name TEXT,
            userPrincipalName TEXT,
            id TEXT,
            displayName TEXT,
            surname TEXT,
            givenName TEXT,
            preferredLanguage TEXT,
            mail TEXT,
            mobilePhone TEXT,
            jobTitle TEXT,
            officeLocation TEXT            
        )''')

        self.cursor.execute('''CREATE TABLE IF NOT EXISTS GoogleEntity (
            vendor_id TEXT UNIQUE,
            vendor_name TEXT,
            id TEXT,
            email TEXT,
            verified_email INTEGER,
            picture TEXT
        )''') 
        self.conn.commit() 

    def insert_vendor_entity_data(self, vendor_id, vendor_name):
        # Insert data into the VendorEntity table
        self.cursor.execute('''
            INSERT OR IGNORE INTO VendorEntity (vendor_id, vendor_name)
            VALUES (?, ?)
        ''', (vendor_id, vendor_name))
        self.conn.commit()

    def insert_microsoft_entity_data(self, vendor_id, vendor_name, userPrincipalName, id, displayName, surname, givenName, preferredLanguage, mail, mobilePhone, jobTitle, officeLocation, businessPhones):
        # Insert data into the MicrosoftEntity table
        self.cursor.execute('''
            INSERT OR IGNORE INTO MicrosoftEntity (vendor_id, vendor_name, userPrincipalName, id, displayName, surname, givenName, preferredLanguage, mail, mobilePhone, jobTitle, officeLocation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (vendor_id, vendor_name, userPrincipalName, id, displayName, surname, givenName, preferredLanguage, mail, mobilePhone, jobTitle, officeLocation))

    def insert_google_entity_data(self, vendor_id, vendor_name, id, email, verified_email, picture):
        try:
            # Insert data into the GoogleEntity table
            self.cursor.execute('''
                INSERT OR IGNORE INTO GoogleEntity (vendor_id, vendor_name, id, email, verified_email, picture)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (vendor_id, vendor_name, id, email, verified_email, picture))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Error: {e}")


def print_keys():
    keys = redis_connection.keys()
    for key in keys:
        print(f"| {key} |")


def extract_users():
    try:
        loader = DataLoader()
        loader.create_tables()
        keys = redis_connection.keys()
        users:list[VendorEntity] = []
        for key in keys:
            if b"MicrosoftUser" in key:            
                userInfo = redis_connection.hgetall(key)
                binary_entity = userInfo[b'VendorEntity']
                des_obj = pickle.loads(binary_entity)
                logger.debug(f"Microsof User [{key}] Info: [{userInfo}]")
                user = MicrosoftEntity(**des_obj.__dict__)
                loader.insert_microsoft_entity_data(user.vendor_id, user.vendor_name, user.userPrincipalName, user.id, user.displayName, user.surname, user.givenName, user.preferredLanguage, user.mail, user.mobilePhone, user.jobTitle, user.officeLocation, user.businessPhones)
            elif b"GoogleUser" in key:           
                userInfo = redis_connection.hgetall(key)
                binary_entity = userInfo[b'VendorEntity']
                des_obj = pickle.loads(binary_entity)
                logger.debug(f"Google User [{key}] Info: [{userInfo}]")
                user = GoogleEntity(**des_obj.__dict__)
                loader.insert_google_entity_data(user.vendor_id, user.vendor_name, user.id, user.email, user.verified_email, user.picture)            
            users.append(user)
    except Exception as e:
        logger.error(f"Error: {e}")
    finally:
        loader.conn.commit()
        loader.conn.close()






    



if __name__ == "__main__":
    extract_users()    
    