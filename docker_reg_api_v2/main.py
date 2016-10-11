import requests
import json
import os
import sys
import urllib2
from urlparse import urlunsplit

SCHEME = 'https'
HOST = 'registry-1.docker.io'


def get_endpoint(reponame, action, scheme=SCHEME, host=HOST, **action_params):
    path = '/v2'
    if reponame:
        path = '/'.join([path, reponame])
    if action:
        action = action.format(**action_params)
        path = '/'.join([path, action])

    return urlunsplit((scheme, host, path, None, None))


def get_auth(service, docker_cfg=os.path.join(os.getenv("HOME"), '.docker', 'config.json')):
    with open(docker_cfg) as fp:
        config = json.load(fp)
        return config['auths'][service]['auth']
    

def get_bearer(response):
    www_authenticate = response['www-authenticate']
    kv_list = urllib2.parse_http_list(www_authenticate)
    kvs = urllib2.parse_keqv_list(kv_list)

    auth_endpoint = kvs['Bearer realm']
    service = kvs['service']

    params = dict(kvs)
    del params['Bearer realm']
    print params

    headers = {
        "Authorization": "Basic %s" % (get_auth(service),) }

    auth_response = requests.get(auth_endpoint, params=params, headers=headers)
    token = auth_response.json()['token']
    return token
    

def reg_request(endpoint, extra_headers=None):
    response = requests.get(endpoint)

    if response.status_code == 200:
        return response

    if response.status_code == 401:
        bearer = get_bearer(response.headers)

        headers = {'Authorization': 'Bearer %s' % (bearer,)}

        if extra_headers:
            for k, v in extra_headers.items():
                headers[k] = v
            
        response = requests.get(endpoint, headers=headers)
        response.raise_for_status()
        return response


def main():
    reponame = 'teradatalabs/dns'
    reg_request(get_endpoint(None, None)).json()
    tags = reg_request(get_endpoint(reponame, 'tags/list'))
    tag_list = tags.json()['tags']
    print tag_list
    if not tag_list:
        print "No tags :-("
        sys.exit(0)
    tag = tag_list[0]

    manifest = reg_request(get_endpoint(reponame, 'manifests/{tag}', tag=tag))
    print manifest
    print json.dumps(manifest.json(), indent=4, separators=(',', ': '))
