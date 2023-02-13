#!/usr/bin/env python

import json
from ChefAPI import ChefAPI
from pprint import PrettyPrinter
pp = PrettyPrinter()

with open('./chef_settings.json', 'r') as f:
    settings = json.load(f)

chef = ChefAPI(settings['url'], settings['keyfile'], settings['username'], settings['verify_ssl'])
chef = ChefAPI('https://cascadia', '../OLD/tony-chef.pem', 'tony', verify=False)

h = chef.headers('/license', 'GET')
print("-----------------------REQUEST HEADERS")
pp.pprint(h)

x = chef.get('/license')
print(f"-----------------------RESPONSE {x.status_code}")
pp.pprint(x.headers)
pp.pprint(x.json())
