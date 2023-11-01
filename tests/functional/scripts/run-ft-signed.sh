#!/bin/bash -x

CLI_VERSION=$1
# Install required dependencies for Functional Tests
apt update
apt install -y make wget git curl
pip install -r ${UMBRELLA_PATH}/requirements.txt

curl http://web:8080
if [[ $? -eq 0 ]]; then
    export METADATA_BASE_URL=http://web:8080
    ONLINE_KEY_ID=f7a6872f297634219a80141caa2ec9ae8802098b07b67963272603e36cc19fd8
    ONLINE_KEY_KEY_TYPE=ed25519
    ONLINE_PUBLIC_KEY=9fe7ddccb75b977a041424a1fdc142e01be4abab918dc4c611fbfe4a3360a9a8
else
    # using localstack for AWS
    export METADATA_BASE_URL=http://localstack:4566/tuf-metadata
    export PERFORMANCE=False
    pip install awscli awscli-local
    # export ONLINE_KEY_ID=${AWS_KEYID}
    # export ONLINE_KEY_KEY_TYPE=rsa
    # ONLINE_PUBLIC_KEY=$(awslocal kms get-public-key --key-id alias/online-key | grep "PublicKey" | awk '{ print $2 }' | sed  's/"//g' | sed 's/,//g')
    ONLINE_KEY_ID=alias/online-key
    ONLINE_KEY_TYPE=rsa
    ONLINE_KEY_SCHEME=rsassa-pss-sha256
    # We have to use endpoint URL as we are running this from a new container.
    ONLINE_PUBLIC_KEY=$(awslocal kms get-public-key --endpoint-url http://localstack:4566/ --key-id alias/online-key | grep "PublicKey" | awk '{ print $2 }' | sed  's/"//g' | sed 's/,//g')
    echo ONLINE PUBLIC KEY: ${ONLINE_PUBLIC_KEY}
    # exit 0
#     ONLINE_SECURESYSTEMSLIB_KEYID=$(python <<END
# from securesystemslib.signer._utils import compute_default_keyid
# import os

# keyid = compute_default_keyid(
#     os.getenv('ONLINE_KEY_TYPE'),
#     os.getenv('ONLINE_KEY_SCHEME'),
#     os.getenv('ONLINE_PUBLIC_KEY'),
# )
# print(keyid)
# END
# )




# Required by botocore used in AWSSigner.import_()
# export AWS_ACCESS_KEY_ID=access_key
# export AWS_SECRET_ACCESS_KEY=secret_key
# export AWS_DEFAULT_REGION=us-east-1
# export AWS_ENDPOINT_URL=http://localstack:4566/

# ONLINE_KEY_INFO=$(python <<END
# from securesystemslib.signer._aws_signer import AWSSigner
# import os

# _, public_key = AWSSigner.import_('alias/online-key', 'rsassa-pss-sha256')

# print(f'{public_key.keyid},{public_key.keyval["public"]}')
# END
# )


# ONLINE_KEY_ID=$(echo $ONLINE_KEY_INFO | awk -F ',' '{print $1}' | sed 's/ //g')
# ONLINE_PUBLIC_KEY=$(echo $ONLINE_KEY_INFO | awk -F ',' '{print $2}' | sed 's/ //g')

fi




# PYTHON_CODE=$(cat <<END
# # python code starts here
# from securesystemslib.signer._utils import compute_default_keyid

# keyid = compute_default_keyid(
#     $ONLINE_KEY_KEY_TYPE, $ONLINE_KEY_KEY_SCHEME, $ONLINE_PUBLIC_KEY
# )
# print(keyid)

# END
# )



# PYTHON_CODE=$(from securesystemslib.signer._utils import compute_default_keyid; print(compute_default_keyid($ONLINE_KEY_KEY_TYPE, $ONLINE_KEY_KEY_SCHEME, $ONLINE_PUBLIC_KEY)))
# ONLINE_SECURESYSTEMSLIB_KEYID=$(python -c ${PYTHON_CODE})



# Install CLI
case ${CLI_VERSION} in
    v*)
        pip install repository-service-tuf==${CLI_VERSION}
        ;;

    latest)
        pip install repository-service-tuf
        pip install --upgrade repository-service-tuf
        ;;

    source) # it install froom the source code (used by CLI)
        pip install -e .
        ;;

    *) # dev or none
        # pip install git+https://github.com/repository-service-tuf/repository-service-tuf-cli
        pip install ./cli
        ;;
esac

# INPUT="{
#     "Do you want more information about roles and responsibilities?": "n",
#     "Do you want to start the ceremony?": "y",
#     "What is the metadata expiration for the root role?": "365",
#     "What is the number of keys for the root role?": "2",
#     "What is the key threshold for root role signing?": "1",
#     "What is the metadata expiration for the targets role?": "365",
#     "Show example?": "n",
#     "Choose the number of delegated hash bin roles": "4",
#     "What is the targets base URL": "http://rstuf.org/downloads",
#     "What is the metadata expiration for the snapshot role?": "1",
#     "What is the metadata expiration for the timestamp role?": "1",
#     "What is the metadata expiration for the bins role?": "1",
#     "Choose ONLINEs key type ": ${$ONLINE_KEY_TYPE}
#     + 

# Execute the Ceremony full signed
python ${UMBRELLA_PATH}/tests/functional/scripts/rstuf-admin-ceremony.py '{
    "Do you want more information about roles and responsibilities?": "n",
    "Do you want to start the ceremony?": "y",
    "What is the metadata expiration for the root role?": "365",
    "What is the number of keys for the root role?": "2",
    "What is the key threshold for root role signing?": "1",
    "What is the metadata expiration for the targets role?": "365",
    "Show example?": "n",
    "Choose the number of delegated hash bin roles": "4",
    "What is the targets base URL": "http://rstuf.org/downloads",
    "What is the metadata expiration for the snapshot role?": "1",
    "What is the metadata expiration for the timestamp role?": "1",
    "What is the metadata expiration for the bins role?": "1",
    "Choose ONLINEs key type ": "",
    "Choose ONLINEs key scheme": "",
    "Enter ONLINEs key id": "",
    "Enter ONLINEs public key hash": "",
    "Give a name/tag to the online key ": "online v1",
    "Ready to start loading the root keys?": "y",
    "Choose roots key1 type ": "ed25519",
    "Enter the roots private key1 path": "tests/files/key_storage/JanisJoplin.key",
    "Enter the roots private key1 password": "strongPass",
    " Give a name/tag to the key1": "JJ",
    "Select to use private key or public info?": "private",
    "Choose roots key2 type ": "",
    "Enter the roots private key2 path": "tests/files/key_storage/JimiHendrix.key",
    "Enter the roots private key2 password": "strongPass",
    " Give a name/tag to the key2": "JH",
    "Is the online key configuration correct?": "y",
    "Is the root configuration correct?": "y",
    "Is the targets configuration correct?": "y",
    "Is the snapshot configuration correct?": "y",
    "Is the timestamp configuration correct?": "y",
    "Is the bins configuration correct?": "y"
}' $(echo $ONLINE_KEY_TYPE) $(echo $ONLINE_KEY_SCHEME) $(echo $ONLINE_KEY_ID) $(echo $ONLINE_PUBLIC_KEY)


# Bootstrap using fully signed metadata
rstuf admin ceremony -b -u -f payload.json --api-server http://repository-service-tuf-api

# Get initial trusted Root
rm metadata/1.root.json
wget -P metadata/ ${METADATA_BASE_URL}/1.root.json
cp -r metadata ${UMBRELLA_PATH}/

exit 0
make -C ${UMBRELLA_PATH}/ functional-tests-exitfirst

