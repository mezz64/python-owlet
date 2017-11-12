#!/usr/bin/env python

import time

import requests
import logging
__author__ = 'fgorodishter'

# configure logging
logging.basicConfig()
logger = logging.getLogger('owlet')
logger.setLevel(logging.DEBUG)


class Owlet(object):

    def __init__(self, email, password):
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self.properties_url = 'https://ads-field.aylanetworks.com/apiv1/dsns/AC********/properties'

        self.properties = [
            'OXYGEN_LEVEL',
            'HEART_RATE',
        ]

        self._auth_token = None
        self._expire_time = 0
        self.last_time = ''

        self.email = email
        self.password = password

    def _login(self):
        '''Generate a new auth token.'''
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

        logger.debug('Generating token')
        data = requests.post(
            login_url,
            json=login_payload,
            headers=self.headers
        )

        # Example response:
        # {
        #    u'access_token': u'abcdefghijklmnopqrstuvwxyz123456',
        #    u'role': u'EndUser',
        #    u'expires_in': 86400,
        #    u'refresh_token': u'123456abcdefghijklmnopqrstuvwxyz',
        #    u'role_tags': []
        # }

        json_data = data.json()

        # update our auth token
        self._auth_token = json_data['access_token']

        # update our auth expiration time
        self._expire_time = time.time() + json_data['expires_in']

        logger.debug('Auth Token: %s expires at %s', self._auth_token, self._expire_time)

    def get_auth_token(self):
        '''
        Get the auth token.

        If the current token has not expired, return that.
        Otherwise login and get a new token and return that token.
        '''

        # if the auth token doesnt exist or has expired, login to get a new one
        if (self._auth_token is None) or (self._expire_time <= time.time()):
            logger.debug('Auth Token expired, need to get a new one')
            self._login()

        return self._auth_token

    def _auth_request(self, url):
        '''Make a get request using the auth_token headers.'''
        auth_header = {
            'Authorization': 'auth_token ' + self.get_auth_token()
        }
        auth_header.update(self.headers)
        response = requests.get(
            url,
            headers=auth_header
        )
        return response

    def get_data(self):
        while True:
            time.sleep(1)

            output = {}
            for measure in self.properties:
                url = self.properties_url + '/' + measure
                data = self._auth_request(url)
                # woo = dump.dump_all(data)
                # print(woo.decode('utf-8'))
                # print(data, data.text, data.headers)
                data_json = data.json()
                if data_json['property']['data_updated_at'] == self.last_time:
                    logger.debug('.')
                else:
                    logger.debug(
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
