from __future__ import absolute_import
from future.standard_library import hooks

import logging
import threading
import traceback
import uuid

import redis
import requests
import yaml


with hooks():
    from urllib.parse import urlparse


class Updater:
    def __init__(self, config_file, dnsproxy):
        self.log = logging.getLogger('asnfilter.updater')
        self.dnsproxy = dnsproxy
        self._updating = False

        # Read config file
        try:
            with open(config_file) as f:
                config = yaml.load(f.read())
        except:
            self.log.critical('Unable to open config file ' + config_file)
            raise

        self.config = config
        self.log.debug('Loaded configuration from ' + config_file)

        # Establish connection to Redis
        pool = redis.ConnectionPool.from_url(config['asnfilter']['redis'])
        self.redis = redis.StrictRedis(connection_pool=pool)
        self.log.debug('Connected to Redis at ' +
                       config['asnfilter']['redis'])

        self.pubsub = self.redis.pubsub(ignore_subscribe_messages=True)
        self.pubsub.subscribe('asnfilter-updates')

        self.pubsub_thread = self.UpdateChannelThread(self)
        self.pubsub_thread.start()

        self.log.debug('Subscribed to asnfilter-updates')

        # Load hosts and ip blacklists from config into Redis
        self.redis.delete('ASNfilter/sources/hosts_list')
        self.redis.delete('ASNfilter/sources/ips_list')

        for url in config['sources']['hosts']:
            self.redis.sadd('ASNfilter/sources/hosts_list', url)

        for url in config['sources']['ips']:
            self.redis.sadd('ASNfilter/sources/ips_list', url)

    def get_update(self, url):
        try:
            response = requests.head(url)

            if 'Last-Modified' in response.headers:
                current = response.headers['Last-Modified']
            else:
                current = uuid.uuid4().hex

            key = 'ASNfilter/sources/' + url + ':last-modified'

            old = self.redis.get(key)
            if old is None:
                old = b''

            if current == old.decode('utf-8'):
                return None

            self.redis.set(key, current)

            return requests.get(url).text
        except:
            for line in traceback.format_exc().split('\n'):
                self.log.error(line)

            return None

    def populate_from_url(self, url, blacklist):
        self.log.info('Updating from: ' + url)

        key = 'ASNfilter/sources/' + url
        update = self.get_update(url)

        if update is None:
            self.log.info('No update available')
            return

        entries = []
        for line in update.splitlines():
            if line.startswith('#') or line.startswith('/') or \
                    line.isspace() or len(line) == 0:
                continue

            fields = line.split()

            if blacklist == 'ips':
                entries.append(fields[0].strip())
                continue

            if len(fields) > 1:
                if fields[1].strip().startswith('#'):
                    entry = fields[0].strip()
                else:
                    entry = fields[1].strip()
            else:
                entry = fields[0].strip()

            if '/' not in entry:
                entries.append(entry)
            else:
                entries.append(urlparse(entry).netloc)

        key = 'ASNfilter/sources/' + url

        self.redis.delete(key)
        self.redis.sadd(key, *entries)

        self.log.info('Added ' +
                      str(self.redis.scard(key)) + ' entries')

    def updates(self, blacklist):
        members = []
        for url in self.redis.smembers('ASNfilter/sources/' +
                                       blacklist + '_list'):
            url = url.decode('utf-8')

            members.append('ASNfilter/sources/' + url)
            self.populate_from_url(url, blacklist)

        self.redis.sunionstore('ASNfilter/' + blacklist + '_blacklist',
                               members)

        self.log.info('Total: ' +
                      str(self.redis.scard(
                          'ASNfilter/' + blacklist + '_blacklist'
                          )))

    def is_updating(self, updating=None):
        if updating is None:
            return self._updating

        self._updating = updating

        return self._updating

    class UpdateThread(threading.Thread):
        def __init__(self, parent):
            threading.Thread.__init__(self)
            self.parent = parent

        def run(self):
            self.parent.is_updating(True)

            self.parent.log.debug('updating hosts')
            self.parent.updates('hosts')

            self.parent.log.debug('updating ips')
            self.parent.updates('ips')

            self.parent.dnsproxy.factory.load_ips_lists()
            self.parent.is_updating(False)

    class UpdateChannelThread(threading.Thread):
        def __init__(self, parent):
            threading.Thread.__init__(self)

            self.parent = parent

        def run(self):
            for message in self.parent.pubsub.listen():
                if message['type'] == 'message':
                    data = message['data'].decode('utf-8')

                    if data == 'update':
                        if self.parent.is_updating() is False:
                            t = self.parent.UpdateThread(self.parent)
                            t.start()
                        else:
                            self.parent.log.warning(
                                'update already running, skipping'
                            )
                    elif data == 'reload-ips':
                        self.parent.dnsproxy.factory.load_ips_lists()
                    elif data == 'stop-thread':
                        self.parent.log.debug('Exiting update channel thread')
                        break

        def stop(self):
            self.parent.redis.publish('asnfilter-updates', 'stop-thread')
