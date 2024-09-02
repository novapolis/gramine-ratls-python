#!/bin/bash

docker kill $(docker ps -a -q)
docker image rm gsc-ratls-test gsc-ratls-test-unsigned:latest ratls-test:latest

docker build -t ratls-test .

cd gsc-configs/gsc/

./gsc build -c ../config.yaml --rm ratls-test ../gramine.manifest

./gsc sign-image -c ../config.yaml  ratls-test /home/azureuser/.config/gramine/enclave-key.pem

./gsc info-image gsc-ratls-test

cd ../../