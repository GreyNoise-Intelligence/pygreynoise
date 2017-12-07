from setuptools import setup

setup(
    name='pygreynoise',
    version='0.1',
    description='Python wrapper around the GreyNoise APO',
    url='https://github.com/Te-k/pygreynoise',
    author='Tek',
    author_email='tek@randhome.io',
    keywords='security',
    install_requires=['requests'],
    license='MIT',
    packages=['pygreynoise'],
    entry_points= {
        'console_scripts': [ 'greynoise=pygreynoise.cli:main' ]
    }
)
