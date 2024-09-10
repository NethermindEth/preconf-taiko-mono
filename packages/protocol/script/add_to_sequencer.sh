#!/bin/sh

# This script is used to set a sequencer using the SetSequencer.s.sol script
set -e

export PRIVATE_KEY=0xbcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31
export FORK_URL=
PROXY_ADDRESS=0x3c0e871bB7337D5e6A18FDD73c4D9e7567961Ad3 \
ADDRESS=0x6064f756f7F3dc8280C1CfA01cE41a37B5f16df1 \
ENABLED=true \
forge script script/SetSequencer.s.sol:SetSequencer \
    --fork-url $FORK_URL \
    --broadcast \
    --skip-simulation \
    --ffi \
    -vvvv \
    --private-key $PRIVATE_KEY \
    --block-gas-limit 100000000