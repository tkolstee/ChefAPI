# ChefAPI

Python module to connect with Chef API

## Installation

```
virtualenv ./.venv
. ./.venv/bin/activate
pip install -r requirements.txt
```

## Usage
See `testclient.py` for an example of how to start and initialize the module.
Note that `testclient` requires the `chef_settings.json` file and a `.pem` file to work.

## Tests
Unit testing is enabled with PyTest. Just type `pytest` (if pytest is installed) to run the test suite.
