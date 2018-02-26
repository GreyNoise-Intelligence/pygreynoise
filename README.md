# pygreynoise

Python 3 wrapper for the greynoise API, see https://github.com/Grey-Noise-Intelligence/api.greynoise.io and greynoise.io.

To install:
```
git clone https://github.com/Te-k/pygreynoise.git
cd pygreynoise
pip install -r requirements.txt
pip install .
```

## CLI

```
$ greynoise -h
usage: greynoise [-h] {ip,list,tag,config} ...

Request GreyNoise

positional arguments:
  {ip,list,tag,config}  Subcommand
    ip                  Request info on an IP
    list                List GreyNoise Tags
    tag                 Query data for a tag
    config              Configure key file

optional arguments:
  -h, --help            show this help message and exit
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

## Author and license

Pygreynoise was started by [Tek](https://github.com/Te-k) and is published under MIT license. Feel free to open issues and pull requests.
