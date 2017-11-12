#!/usr/bin/env python

import time

import requests

__author__ = 'fgorodishter'


class Owlet(object):

    def __init__(self, email, password):
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self.auth_header = {
            'Authorization': 'auth_token ***'
        }
        self.properties_url = 'https://ads-field.aylanetworks.com/apiv1/dsns/AC********/properties'

        self.properties = [
            'OXYGEN_LEVEL',
            'HEART_RATE',
        ]

        self.auth_token = ''
        self.expire_time = 0
        self.last_time = ''

        self.email = email
        self.password = password

    def login(self):
        login_url = 'https://user.aylanetworks.com:443/users/sign_in.json'
        login_payload = {
          "user": {
            "email": self.email,
            "password": self.password,
            "application": {
              "app_id": "OWL-id",
              "app_secret": "OWL-4163742"
            }
          }
        }

        # print (auth_token, expire_time, time.time())
        if (self.auth_token == '') or (self.expire_time <= time.time()):
            print ('Generating token')
            data = requests.post(
                login_url,
                json=login_payload,
                headers=self.headers
            )
            self.auth_token = data.json()['access_token']
            self.expire_time = time.time() + 3600
            print (self.auth_token)

    def get_data(self):
        while True:
            self.login()
            time.sleep(1)

            self.auth_header = {
                'Authorization': 'auth_token ' + self.auth_token
            }
            self.auth_header.update(self.headers)

            output = {}
            for measure in self.properties:
                url = self.properties_url + '/' + measure
                data = requests.get(url, headers=self.auth_header)
                # woo = dump.dump_all(data)
                # print(woo.decode('utf-8'))
                # print(data, data.text, data.headers)
                data_json = data.json()
                if data_json['property']['data_updated_at'] == self.last_time:
                    print('.')
                else:
                    print (
                        measure,
                        data_json['property']['value'],
                        data_json['property']['data_updated_at']
                    )
                    output.update(
                        {
                            'measure': data_json['property']['value'],
                            'data_updated_at': data_json['property']['data_updated_at']
                        }
                    )

            # log to es
            requests.post(
                'http://ES_ADDRESS:9200/owlet/measure/' + output['data_updated_at'],
                verify=False,
                json=output,
                headers=self.headers
            )

            # if we want to remove duplicate posts, uncomment and fix this
            # last_time = data.json()['property']['data_updated_at']


if __name__ == "__main__":
    import sys

    # get credentials from the commandline
    # python owlet_status.py email password
    email = sys.argv[1]
    password = sys.argv[2]

    o = Owlet(
        email=email,
        password=password
    )
    o.get_data()
