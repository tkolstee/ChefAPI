#!/usr/bin/env python3
import os
import pytest
import tempfile
import json
from datetime import datetime, timedelta
import re
from ..ChefAPI import ChefAPI


@pytest.fixture
def cleandir():
    with tempfile.TemporaryDirectory() as newpath:
        old_cwd = os.getcwd()
        os.chdir(newpath)
        yield newpath
        os.chdir(old_cwd)


@pytest.fixture
def settings():
    mydir = os.path.dirname(__file__)
    file = os.path.join(mydir, 'settings.json')
    with open(file, 'r') as f:
        data = json.load(f)
    return data


@pytest.fixture
def keyfile():
    mydir = os.path.dirname(__file__)
    return os.path.join(mydir, 'test-key.pem')


@pytest.fixture
def chefapi(settings, keyfile):
    return ChefAPI(settings['url'], keyfile, settings['username'])


def test_constructor(settings, keyfile, cleandir):
    x = ChefAPI(settings['url'], keyfile, settings['username'])
    assert type(x) == ChefAPI

    badkey = os.path.join(cleandir, 'badkey.pem')
    with open(badkey, 'w') as f:
        f.write('')
    with pytest.raises(ValueError):
        x = ChefAPI(settings['url'], badkey, settings['username'])

    with pytest.raises(FileNotFoundError):
        x = ChefAPI(settings['url'], '/nonexistent', settings['username'])


def test_cert_verify(settings, keyfile):
    x = ChefAPI(settings['url'], keyfile, settings['username'])
    assert x.verify
    x = ChefAPI(settings['url'], keyfile, settings['username'], False)
    assert not x.verify


def test_content_hash(chefapi):
    assert chefapi.content_hash('') == (
      '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
    )
    assert chefapi.content_hash('foobar') == (
        'w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI='
    )
    assert chefapi.content_hash(b'foobar') == (
        'w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI='
    )


def test_timestamp(chefapi):
    ts = chefapi.timestamp()
    now = datetime.utcnow()
    assert type(ts) == str
    assert re.match(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', ts)
    parsed = datetime.strptime(ts, r'%Y-%m-%dT%H:%M:%SZ')
    assert now - parsed < timedelta(seconds=5)


def test_get_headers(settings, chefapi):
    headers = chefapi.headers('/license', 'GET')
    for key, value in settings['expected_get_headers'].items():
        assert headers[key] == value
    assert 'Content-Type' not in headers
    assert re.match(
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',
        headers['X-Ops-Timestamp']
    )


def test_post_headers(settings, chefapi):
    reqbody = json.dumps(settings['post_data'])
    headers = chefapi.headers('/authenticate_user', 'POST', reqbody)
    for key, value in settings['expected_post_headers'].items():
        assert headers[key] == value
    wanthash = chefapi.content_hash(reqbody)
    assert headers['X-Ops-Content-Hash'] == wanthash


def test_canonical_headers(chefapi, settings):
    headers = settings['sample_headers']
    canon = chefapi.canonical_headers(headers)
    assert canon == settings['canonical_headers']


def test_path_does_not_contain_url_parameters(chefapi, settings):
    endpoint = '/organizations/myorg/search/node'
    query = 'chef_environment:BLAH'
    url = f"{endpoint}?{query}"
    headers = chefapi.headers(url, 'GET')
    assert 'chef_environment' not in headers['Path']
    assert 'BLAH' not in headers['Path']


def test_gen_sig(chefapi, settings):
    canon = settings['canonical_headers']
    sig = chefapi.gen_signature(canon)
    assert sig == settings['signature']


def test_signing_headers(chefapi, settings):
    headers = settings['sample_headers']
    auth = chefapi.signing_headers(headers)
    assert auth == settings['auth_headers']
