from iso8601 import parse_date
from datetime import datetime, timedelta
import json
import os
import requests
import re
import urllib2
from urlparse import urlunsplit
from pytz import utc


SCHEME = 'https'
HOST = 'registry-1.docker.io'
randoms_warn_only = True


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

    headers = {"Authorization": "Basic %s" % (get_auth(service),)}

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


def get_created(reponame, tag):
    manifest = reg_request(
            get_endpoint(reponame, 'manifests/{tag}', tag=tag),
            extra_headers={
                    'Accept': 'application/vnd.docker.distribution.manifest.v2+json'})
    mf = manifest.json()
    config = mf['config']
    digest = config['digest']
    blob = reg_request(get_endpoint(reponame, 'blobs/{blob}', blob=digest))
    top_layer = blob.json()
    created = top_layer['created']
    return parse_date(created), digest


git_tag_re = re.compile('^[0-9A-Fa-f]{7}$')
release_tag_re = re.compile('^[0-9]{1,6}$')
reap_after = timedelta(days=30)


def is_git_tag(tag):
    return git_tag_re.match(tag)


def is_release(tag):
    return release_tag_re.match(tag)


def im_too_young_to_die(now, then):
    age = now - then
    return age < reap_after


exempt_tags = frozenset(['latest', 'latest-snapshot'])


def main():
    reponame = 'ebd2/dns'
    reg_request(get_endpoint(None, None)).json()
    tags_response = reg_request(get_endpoint(reponame, 'tags/list'))
    tags = set(tags_response.json()['tags'])
    if not tags:
        raise Exception('No tags for repository {reponame}'.format(reponame=reponame))
    git_tags = set([tag for tag in tags if is_git_tag(tag)])
    releases = set([tag for tag in tags if is_release(tag)])

    others = tags.difference(git_tags, releases)

    # Sanity check:
    if not git_tags.isdisjoint(releases):
        raise Exception(
                'Found tag(s) in both git tags and releases: {}'
                .format(', '.join(git_tags.intersection(releases))))

    print git_tags
    print releases
    print others

    metadata = {}

    for tag in tags:
        print 'Fetching metadata for {}'.format(tag)
        metadata[tag] = get_created(reponame, tag)

    now = datetime.now(utc)
    cleanup_list = []

    for git_tag in git_tags:
        git_ctime, git_digest = metadata[git_tag]

        if im_too_young_to_die(now, git_ctime):
            continue

        # See if it's the same image as a release.
        for release_tag in releases:
            _, release_digest = metadata[release_tag]
            if release_digest == git_digest:
                continue

        cleanup_list.append((git_tag, git_digest))

    for other_tag in others:
        other_ctime, odigest = metadata[other_tag]

        if other_tag in exempt_tags:
            continue

        if im_too_young_to_die(now, other_ctime):
            continue

        if randoms_warn_only:
            print 'Found old random tag {}'.format(other_tag)
            continue

        cleanup_list.append((other_tag, odigest))

    print 'going to delete tags {}'.format(cleanup_list)
