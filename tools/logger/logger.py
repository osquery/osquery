# For starting it, use run.sh script
import os
from pprint import pprint
from functools import wraps

from flask import Flask, request, jsonify
import yaml

NODE_KEY = '00000000-0000-0000-0000-000000000000'

app = Flask(__name__)


def route(*urls):
    # like app.route, but supports several urls
    # and implies more methods
    def adder(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            """ Jsonify replies, adding node_invalid=false if needed """
            resp = f(*args, **kwargs)
            if resp is None:
                resp = {}
            if isinstance(resp, dict):
                resp.setdefault('node_invalid', False)
                return jsonify(**resp)
            return resp

        for url in urls:
            # register this wrapper for each url
            app.route(url, methods=['GET', 'POST', 'PUT'])(wrapper)
        return wrapper
    return adder


@app.before_request
def request_logging():
    print()
    print('-> {method} {path}'.format(
        method=request.method,
        path=request.path,
    ))
    try:
        json = request.get_json(force=True)
        if json is None:
            print('No data in request')
        else:
            pprint(json)
    except Exception:
        print('Invalid JSON in request:')
        pprint(request.data)


def fill_dict_tpl(tpl, data):
    for key, val in data.items():
        if key not in tpl:
            print('Warning: unknown key %s, ignoring' % key)
            continue
        if type(tpl[key]) != type(val):
            print(
                'Warning: wrong data type for key <%s>: '
                'expected <%s>, got <%s>' % (
                    key, type(tpl[key]).__name__, type(val).__name__,
                )
            )
        elif tpl[key]:
            if not isinstance(tpl[key], dict):
                # should not happen
                raise ValueError('Unexpected <%r> in <%r>' % (tpl[key], tpl))
            fill_dict_tpl(tpl[key], val)
        else:
            tpl[key] = val


def read_yaml(name, template):
    path = os.path.join(
        os.path.dirname(__file__),
        name,
    )
    if not os.path.exists(path):
        return template

    with open(name, 'r') as f:
        try:
            data = yaml.safe_load(f)
        except Exception as e:
            print('Failed to parse YAML file <%s>' % name)
            print(e)
            return template

    if data is None:
        # empty file
        return template

    if not isinstance(data, dict):
        print('Incorrect data format: expected mapping, got <%s>' %
              type(data).__name__)
        return template

    fill_dict_tpl(template, data)

    return template


@route('/')
def index():
    return '', 204


@route('/log', '/distributed/write',
       '/v1/log', '/v1/distributed/write')
def simple_endpoint():
    pass


@route('/enroll', '/v1/enroll')
def enroll():
    return dict(
        # we always return zero-filled GUID for node key
        node_key=NODE_KEY,
    )


@route('/config', '/v1/config')
def config():
    tpl = dict(
        options=dict(
            # variants: uuid or hostname
            host_identifier='uuid',
            # in doorman it is hardcoded
            schedule_splay_percent=10,
        ),
        # mapping: category -> list of paths
        file_paths={},
        # mapping: name -> {query, interval, platform, version,
        #                   description, value, removed}
        schedule={},
        # mapping: name -> {platform, version, shard, discovery, queries}
        # where discovery is list of sqls
        # and queries is mapping, like in `schedule` field
        packs={},
    )
    return read_yaml('config.yml', tpl)


@route('/distributed/read', '/v1/distributed/read')
def distributed_read():
    return dict(
        # new queries only
        # (each task should only be returned once)
        # mapping: guid -> sql
        queries=read_yaml('tasks.yml', {}),
    )
