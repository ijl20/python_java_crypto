#!/bin/bash

echo =====PYTHON
source venv/bin/activate
python python/AES.py
echo =====JAVA
java -cp java AESCrypt

