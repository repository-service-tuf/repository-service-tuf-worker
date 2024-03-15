#!/usr/bin/env bash
awslocal kms create-key \
    --key-spec RSA_4096 \
    --key-usage SIGN_VERIFY

awslocal kms create-alias \
    --alias-name alias/aws-test-key \
    --target-key-id $(awslocal kms list-keys --query "Keys[0].KeyId" --output text)
