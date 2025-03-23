#! /usr/bin/env bash

GITHUB_TOKEN="TEST_TOKEN HERE"

curl -H 'Authorization: token $GITHUB_TOKEN' \
  -H 'Accept: application/vnd.github.v3.raw' \
  -O \
  -L https://api.github.com/repos/snak613/bl_gen/contents/out/domains.json

echo $GITHUB_TOKEN