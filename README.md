# pygreynoise

Python 3 wrapper for the greynoise API, see https://github.com/Grey-Noise-Intelligence/api.greynoise.io and greynoise.io.

To install:
```
git clone https://github.com/Te-k/pygreynoise.git
cd pygreynoise
pip install .
```

## CLI

```
$ greynoise -h
usage: greynoise [-h] [--list] [--ip IP] [--tag TAG]

Request GreyNoise

optional arguments:
  -h, --help         show this help message and exit
  --list, -l         List tags
  --ip IP, -i IP     Query an IP address
  --tag TAG, -t TAG  Query a tag
```

## Library

```python
from pygreynoise import GreyNoise

gn = GreyNoise()
tags = gn.tags()

try:
    gn.query_ip('198.20.69.74')
except GreyNoiseError:
    print('IP not found')

try:
    gn.query_tag('YANDEX_SEARCH_ENGINE')
except GreyNoiseError:
    print('This tag does not exist')
```

