#!/bin/bash

cd /tmp
touch sleigh
for reindeer in dasher dancer prancer vixen comet cupid donner blitzen; do
    ln sleigh $reindeer
done
