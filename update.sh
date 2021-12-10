#!/bin/bash

git pull
sudo insmod pprotect.ko
sudo chmod 777 /dev/etx_device
