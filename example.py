import os

from flask import Flask
from flask import jsonify
app = Flask(__name__)

from azure.keyvault import KeyVaultClient
from msrestazure.azure_active_directory import MSIAuthentication, ServicePrincipalCredentials
from azure.storage.blob import BlockBlobService


KEY_VAULT_URI = "<PLACEHOLDER>"
STORAGE_ACCOUNT = "<PLACEHOLDER>"
STORAGE_CONTAINER = "<PLACEHOLDER>"

# For local debugging instead of MSI, create app registration and fill the following data: 
SERVICE_PRINCIPAL_TENANT_ID="<PLACEHOLDER>7"
SERVICE_PRINCIPAL_CLIENT_ID="<PLACEHOLDER>"
SERVICE_PRINCIPAL_CLIENT_SECRET="<PLACEHOLDER>"

def get_key_vault_credentials():
    """This tries to get a token using MSI, or fallback to SP env variables.
    """
    if "APPSETTING_WEBSITE_SITE_NAME" in os.environ:
        return MSIAuthentication(
            resource='https://vault.azure.net'
        )
    else:
        return ServicePrincipalCredentials(
            client_id=os.environ.get("APPSETTING_SERVICE_PRINCIPAL_CLIENT_ID", SERVICE_PRINCIPAL_CLIENT_ID),
            secret=os.environ.get("APPSETTING_SERVICE_PRINCIPAL_CLIENT_SECRET", SERVICE_PRINCIPAL_CLIENT_SECRET),
            tenant=os.environ.get("APPSETTING_SERVICE_PRINCIPAL_TENANT_ID", SERVICE_PRINCIPAL_TENANT_ID),
            resource='https://vault.azure.net'
        )

def get_blob_storage_credentials(account_name):
    """This tries to get a token using MSI, or fallback to SP env variables.
    """

    if "APPSETTING_WEBSITE_SITE_NAME" in os.environ:
        return MSIAuthentication(
            resource='https://{account_name}.blob.core.windows.net'.format(
                account_name=account_name
            )
        )
    else:
        return ServicePrincipalCredentials(
            client_id=os.environ.get("APPSETTING_SERVICE_PRINCIPAL_CLIENT_ID", SERVICE_PRINCIPAL_CLIENT_ID),
            secret=os.environ.get("APPSETTING_SERVICE_PRINCIPAL_CLIENT_SECRET", SERVICE_PRINCIPAL_CLIENT_SECRET),
            tenant=os.environ.get("APPSETTING_SERVICE_PRINCIPAL_TENANT_ID", SERVICE_PRINCIPAL_TENANT_ID),
            resource='https://{account_name}.blob.core.windows.net'.format(account_name=account_name)
        )

def msi_keyvault_secret():
    """MSI Authentication example with Key Vault"""

    # Get credentials
    credentials = get_key_vault_credentials()

    # Create a KeyVault client
    key_vault_client = KeyVaultClient(
        credentials
    )

    key_vault_uri = os.environ.get("APPSETTING_KEY_VAULT_URL", KEY_VAULT_URI)

    secret = key_vault_client.get_secret(
        key_vault_uri,  # Your KeyVault URL
        "secret",       # Name of your secret. If you followed the README 'secret' should exists
        ""              # The version of the secret. Empty string for latest
    )

    return "My secret value is {}".format(secret.value)

def msi_blob_files():
    """MSI Authentication example with blob storage"""

    # Get the storage account name from app settings
    account_name = os.environ.get("APPSETTING_STORAGE_ACCOUNT", STORAGE_ACCOUNT)
    container_name = os.environ.get("APPSETTING_STORAGE_CONTAINER", STORAGE_CONTAINER)

    # Get blob storage token credential
    token_credential = get_blob_storage_credentials(account_name)

    block_blob_service = BlockBlobService(
                    account_name=account_name,
                    token_credential=token_credential)

    blobslist = block_blob_service.list_blobs(container_name)

    blobfiles = []
    for blob in blobslist:
        print("\t Blob name: " + blob.name)
        blobfiles.append(blob.name)

    return jsonify(blobfiles)


@app.route('/')
def hello_world():
    return "Try /secret or /blob endpoints"

@app.route('/secret')
def secret():
    try:
        return msi_keyvault_secret()
    except Exception as err:
        return str(err)

@app.route('/blob')
def blob():
    try:
        return msi_blob_files()
    except Exception as err:
        return str(err)

@app.route('/ping')
def ping():
    return "Hello world"

if __name__ == '__main__':
  app.run()