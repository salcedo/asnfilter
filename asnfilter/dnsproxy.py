import encodings.idna
import logging
import os
import pwd
import socket
import traceback

import geoip2.database
import redis
import yaml

from netaddr import IPAddress, IPNetwork

from twisted.internet import reactor, defer
from twisted.names import client, dns, error, server
from twisted.names.dns import A, AAAA

from asnfilter.metrics import Metric

idna = encodings.idna


class DNSProxy:
    def __init__(self, config_file, geolite2_db=None, port=None, resolv=None,
                 user='nobody'):
        self.log = logging.getLogger('asnfilter.dnsproxy')
        self.port = port
        self.user = user

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
        self.log.debug('Connected to Redis at ' + config['asnfilter']['redis'])

        # Open MaxMind GeoLite2 ASN Database
        try:
            if geolite2_db:
                asndb = geolite2_db
            else:
                asndb = config['dnsproxy']['asndb']

            self.reader = geoip2.database.Reader(asndb)
        except:
            self.log.critical('Unable to open MaxMind GeoLite2 ASN database ' +
                              asndb)
            raise

        self.log.debug('Read MaxMind GeoLite2 ASN database from ' + asndb)

        if resolv is None:
            self.log.debug('Using upstream servers from config file')

            servers = []
            for entry in config['dnsproxy']['servers']:
                servers.append((entry, 53))

            self.factory = self.DNSServerFactory(
                redis=self.redis,
                reader=self.reader,
                clients=[
                    self.Resolver(
                        redis=self.redis,
                        servers=servers
                    )
                ]
            )
        else:
            self.log.debug('Using upstream servers from /etc/resolv.conf')

            self.factory = self.DNSServerFactory(
                redis=self.redis,
                reader=self.reader,
                clients=[
                    self.Resolver(
                        redis=self.redis,
                        resolv=resolv
                    )
                ]
            )

        # Instantiate reactor
        if port is None:
            self.port = config['dnsproxy']['port']

        protocol = dns.DNSDatagramProtocol(controller=self.factory)

        self.reactor = reactor
        self.reactor.listenUDP(self.port, protocol)
        self.reactor.listenTCP(self.port, self.factory)

    def run(self):
        if not self.drop_privileges():
            raise Exception('Unable to drop privileges')

        self.log.info('Starting ASNfilter DNS Proxy on port ' +
                      str(self.port))

        self.reactor.run()

    def stop(self):
        self.reactor.stop()

    def drop_privileges(self):
        if os.getuid() != 0:
            return True

        try:
            pw = pwd.getpwnam(self.user)
        except:
            self.log.error(
                'Unable to drop privileges. User %s not found.' % self.user
            )
            return False

        uid = pw.pw_uid
        if uid == 0:
            self.log.error(
                'Unable to drop privileges. User %s is a super-user.' %
                self.user
            )
            return False

        gid = pw.pw_gid

        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)

        os.umask(0o77)
        os.environ['HOME'] = pw.pw_dir

        return True

    class Resolver(client.Resolver):
        def __init__(self, redis, resolv=None, servers=None,
                     timeout=(1, 3, 11, 45), reactor=None):
            self.redis = redis
            self.metric = Metric(self.redis)
            self.log = logging.getLogger('asnfilter.dnsproxy.query')
            self._queryUDP = client.Resolver.queryUDP
            self._queryTCP = client.Resolver.queryTCP

            client.Resolver.__init__(self, resolv, servers, timeout, reactor)

        def queryUDP(self, queries, timeout=None):
            self.metric.query()

            self.log.debug('Received UDP queries')

            if self.queriesFilter(queries):
                return defer.fail(error.DomainError())
            else:
                return self._queryUDP(self, queries, timeout)

        def queryTCP(self, queries, timeout=10):
                self.metric.query()

                self.self.log.debug('Received TCP queries')

                if self.queriesFilter(queries):
                    return defer.fail(error.DomainError())
                else:
                    return self._queryTCP(self, queries, timeout)

        def queriesFilter(self, queries):
            for query in queries:
                name = query.name.name.decode('utf-8').lower()

                if self.redis.sismember('ASNfilter/hosts_whitelist', name):
                    self.log.info('Allowed because ' + name +
                                  ' in hosts whitelist')
                    self.metric.host_allowed({'host': name})

                    return False

                if self.redis.sismember('ASNfilter/hosts_blacklist', name):
                    self.log.info('Denied because ' + name +
                                  ' in hosts blacklist')
                    self.metric.host_denied({'host': name})

                    return True

            self.log.debug(
                'Allowed queries because they did not match any rules')

            return False

    class DNSServerFactory(server.DNSServerFactory):
        def __init__(self, redis, reader, authorities=None, caches=None,
                     clients=None, verbose=0):
            self.log = logging.getLogger('asnfilter.dnsproxy.response')
            self.redis = redis
            self.reader = reader
            self.metric = Metric(self.redis)
            self._sendReply = server.DNSServerFactory.sendReply

            server.DNSServerFactory.__init__(self, authorities, caches,
                                             clients, verbose)
            self.load_ips_lists()

        def sendReply(self, protocol, message, address):
            filtered = False
            for answer in message.answers:
                if answer.type == A:
                    ip_address = answer.payload.dottedQuad()

                    if self.replyFilter(ip_address):
                        filtered = True
                        break
                elif answer.type == AAAA:
                    ip_address = socket.inet_ntop(socket.AF_INET6,
                                                  answer.payload.address)

                    if self.replyFilter(ip_address):
                        filtered = True
                        break
                else:
                    continue

            if filtered is True:
                message.rCode = 3  # NXDOMAIN
                message.answers = []

            self.log.debug('Sending response to %s:%d' % address)

            return self._sendReply(self, protocol, message, address)

        def replyFilter(self, ip_address):
            try:
                if self._match_ip(ip_address, self.ips_whitelist):
                    self.log.info('Allowed because ' + ip_address +
                                  ' in IPs whitelist')
                    self.metric.ip_allowed({'ip': ip_address})

                    return False

                if self._match_ip(ip_address, self.ips_blacklist):
                    self.log.info('Denied because ' + ip_address +
                                  ' in IPs blacklist')
                    self.metric.ip_denied({'ip': ip_address})

                    return True

                (asn, organization) = self._get_ASN(ip_address)

                self.redis.sadd('ASNfilter/ASNs', asn)
                self.redis.set('ASNfilter/ASN/' + asn, organization)

                self.log.debug('Added ASN ' + asn + ' (' + organization + ')')

                if self.redis.sismember('ASNfilter/asns_whitelist', asn):
                    self.log.info('Allowed because ' + ip_address +
                                  ' in ASNs whitelist:' + asn +
                                  ' (' + organization + ')')
                    self.metric.asn_allowed(
                            {'asn': asn, 'organization': organization}
                        )

                    return False

                if self.redis.sismember('ASNfilter/asn_blacklist', asn):
                    self.log.info('Denied because ' + ip_address +
                                  ' in ASN blacklist:' + asn +
                                  ' (' + organization + ')')
                    self.metric.asn_denied(
                            {'asn': asn, 'organization': organization}
                        )

                    return True
            except:
                self.log.error('Error in responseFilter:\n' +
                               traceback.format_exc())
                return False

            self.log.debug('Allowed because ' + ip_address +
                           ' did not match any rules.')

            return False

        def load_ips_lists(self):
            self.ips_whitelist = self.redis.smembers('ASNfilter/ips_whitelist')
            self.ips_blacklist = self.redis.smembers('ASNfilter/ips_blacklist')

            self.log.info('Loaded IPs lists')

        def _get_ASN(self, ip_address):
            try:
                result = self.reader.asn(ip_address)
            except:
                raise

            asn = str(result.autonomous_system_number)
            organization = result.autonomous_system_organization

            return (asn, organization)

        def _match_ip(self, ip_address, ip_list):
            for ip in ip_list:
                if IPAddress(ip_address) in IPNetwork(ip.decode('utf-8')):
                    return True

            return False
