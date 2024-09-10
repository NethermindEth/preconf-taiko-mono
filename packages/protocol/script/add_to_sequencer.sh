#!/bin/sh

# This script is used to set a sequencer using the SetSequencer.s.sol script
set -e

export PRIVATE_KEY=0xbcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31
export FORK_URL=
PROXY_ADDRESS=0x72bCbB3f339aF622c28a26488Eed9097a2977404 \
ADDRESS=0x \
ENABLED=true \
forge script script/SetSequencer.s.sol:SetSequencer \
    --fork-url $FORK_URL \
    --broadcast \
    --skip-simulation \
    --ffi \
    -vvvv \
    --private-key $PRIVATE_KEY \
    --block-gas-limit 100000000