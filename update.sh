#!/bin/bash

git pull
make clean
make
sudo insmod pprotect.ko

"
