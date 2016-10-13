from iso8601 import parse_date
import iso8601 # noqa F401 (Used by eval() when loading manifests)
import datetime
import json
import os
import requests
import re
import urllib2
from urlparse import urlunsplit
from pytz import utc
from pprint import pprint
from argparse import ArgumentParser
import sys

SCHEME = 'https'
HOST = 'registry-1.docker.io'

BEARER_REALM_ALIASES = {
        'registry.docker.io': ['registry-1.docker.io']
}

def get_endpoint(reponame, action, scheme=SCHEME, host=HOST, **action_params):
    path = '/v2'
    if reponame:
        path = '/'.join([path, reponame])
    if action:
        action = action.format(**action_params)
        path = '/'.join([path, action])

    return urlunsplit((scheme, host, path, None, None))


def get_auth(service, docker_cfg=os.path.join(os.getenv("HOME"), '.docker', 'config.json')):
    services = list(service)
    services.extend(BEARER_REALM_ALIASES.get(service, []))

    with open(docker_cfg) as fp:
        config = json.load(fp)
        for service_candidate in services:
            try:
                return config['auths'][service_candidate]['auth']
            except KeyError:
                pass
        raise Exception("No auth token for service {service}. Try `docker login {service}'".format(service=service))


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


def reg_request(
        endpoint,
        extra_headers=None,
        verb=requests.get,
        raise_for_status=True):
    response = verb(endpoint)

    if response.status_code == 200:
        return response

    if response.status_code == 401:
        bearer = get_bearer(response.headers)

        headers = {'Authorization': 'Bearer %s' % (bearer,)}

        if extra_headers:
            for k, v in extra_headers.items():
                headers[k] = v

        response = verb(endpoint, headers=headers)
        if raise_for_status:
            response.raise_for_status()
        return response


def get_metadata(reponame, tag):
    manifest = reg_request(
            get_endpoint(reponame, 'manifests/{tag}', tag=tag),
            extra_headers={
                    'Accept': 'application/vnd.docker.distribution.manifest.v2+json'})
    mf = manifest.json()
    config = mf['config']
    delete_identifier = manifest.headers['Docker-Content-Digest']
    digest = config['digest']
    blob = reg_request(get_endpoint(reponame, 'blobs/{blob}', blob=digest))
    top_layer = blob.json()
    created = top_layer['created']
    return parse_date(created), delete_identifier


git_tag_re = re.compile('^[0-9A-Fa-f]{7}$')
release_tag_re = re.compile('^[0-9]{1,6}$')


def is_git_tag(tag):
    return git_tag_re.match(tag)


def is_release(tag):
    return release_tag_re.match(tag)


def im_too_young_to_die(now, then, max_age):
    age = now - then
    return age < max_age


EXEMPT_TAGS = frozenset(['latest'])


def get_live_tags(reponame):
    tags_response = reg_request(get_endpoint(reponame, 'tags/list'))
    tags = set(tags_response.json()['tags'])
    if not tags:
        raise Exception('No tags for repository {reponame}'.format(reponame=reponame))
    return tags


def classify_tags(tags):
    git_tags = frozenset([tag for tag in tags if is_git_tag(tag)])
    releases = frozenset([tag for tag in tags if is_release(tag)])
    others = tags.difference(git_tags, releases)

    # Sanity check:
    if not git_tags.isdisjoint(releases):
        raise Exception(
                'Found tag(s) in both git tags and releases: {}'
                .format(', '.join(git_tags.intersection(releases))))

    return (git_tags, releases, others)


def get_live_metadata(reponame, tags):
    metadata = {}
    for tag in tags:
        print 'Fetching metadata for {}'.format(tag)
        metadata[tag] = get_metadata(reponame, tag)
    return metadata


def find_cleanup(metadata, candidates, exempt, max_age):
    now = datetime.datetime.now(utc)
    cleanup_list = []

    for candidate in candidates:
        cand_ctime, _ = metadata[candidate]
        if candidate in exempt:
            continue

        if im_too_young_to_die(now, cand_ctime, max_age):
            continue
        cleanup_list.append(candidate)

    return cleanup_list


def cleanup(reponame, metadata, args):
    git_tags, releases, others = classify_tags(frozenset(metadata.keys()))

    max_age = datetime.timedelta(args.days)

    cleanup_list = []
    cleanup_list.extend(find_cleanup(metadata, git_tags, [], max_age))
    cleanup_list.extend(find_cleanup(metadata, others, EXEMPT_TAGS, max_age))

    for tag in cleanup_list:
        print "Deleting {}:{}".format(reponame, tag)
        if args.dry_run:
            print 'DRY RUN - SKIPPING DELETE'
            continue

        _, delete_identifier = metadata[tag]
        delete_endpoint = get_endpoint(reponame, 'manifests/{digest}', digest=delete_identifier)
        print delete_endpoint
        response = reg_request(delete_endpoint, verb=requests.delete, raise_for_status=False)
        print response.headers
        print response.text


def main():
    parser = ArgumentParser("Clean up old images from a docker registry")
    parser.add_argument('--dry-run', action='store_true', default=False)
    parser.add_argument('--days', type=int, default=30)
    metadata_group = parser.add_mutually_exclusive_group()
    metadata_group.add_argument('--metadata', type=str, default=None)
    metadata_group.add_argument('--dump-metadata', type=str, default=None)
    parser.add_argument('reponames', type=str, help="Repository names to clean up", nargs='*')
    args = parser.parse_args()

    if args.metadata:
        with open(args.metadata, 'r') as metafile:
            metastring = metafile.read()
            metastring = metastring.replace('<iso8601.Utc>', 'iso8601.UTC')
            reponame, metadata = eval(metastring)
        cleanup(reponame, metadata, args)
        sys.exit(0)

    for reponame in args.reponames:
        tags = get_live_tags(reponame)
        metadata = get_live_metadata(reponame, tags)

        if args.dump_metadata:
            with open(args.dump_metadata, 'w') as metafile:
                pprint((reponame, metadata), stream=metafile, indent=4)

        cleanup(reponame, metadata, args)
