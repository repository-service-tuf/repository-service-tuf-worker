#!/usr/bin/env bash

vault server -dev -dev-root-token-id="${RSTUF_VAULT_TOKEN}" &

export VAULT_ADDR=${RSTUF_VAULT_ADDR}

until vault status
do
    sleep 0.1
done

vault secrets enable transit
vault write -force transit/keys/test-key-ed25519 type=ed25519
