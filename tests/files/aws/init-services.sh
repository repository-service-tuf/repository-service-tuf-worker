#!/usr/bin/env bash
# Prepare AWSS3
awslocal s3 mb s3://tuf-metadata

# Prepare AWSKMS
awslocal kms create-key --key-usage SIGN_VERIFY --key-spec RSA_2048 --region us-east-1
AWS_KEYID=$(awslocal kms list-keys | grep "KeyId" | awk '{ print $2 }' | sed  's/"//g' | sed 's/,//g')
awslocal kms create-alias --region us-east-1 --alias-name alias/online-key --target-key-id ${AWS_KEYID}
