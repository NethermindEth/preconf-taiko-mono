#!/bin/sh

# This script is used to set a sequencer using the SetSequencer.s.sol script
set -e

forge script script/SetSequencer.s.sol:SetSequencer \
    --fork-url $FORK_URL \
    --broadcast \
    --skip-simulation \
    --ffi \
    -vvvv \
    --private-key $PRIVATE_KEY \
    --block-gas-limit 100000000
