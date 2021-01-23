#!/bin/bash
GOOS=linux go build -o gogoauth && scp gogoauth sf:/root/gogoauth/
