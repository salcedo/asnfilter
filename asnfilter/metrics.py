import json


class Metric(object):
    """
    Object for gathering and storing metrics for ASNfilter
    Argument: Redis instance
    """
    def __init__(self, redis):
        self.redis = redis

        self.metrics = ['ips_allowed', 'ips_denied', 'asns_allowed',
                        'asns_denied', 'hosts_allowed', 'hosts_denied',
                        'total_queries']

        for metric in self.metrics:
            key = 'ASNfilter/metrics/' + metric
            if not self.redis.exists(key):
                self.redis.set(key, 0)

    def ip_allowed(self, data):
        """
        IP was allowed by whitelist
        """
        self._tick('ips_allowed')
        self._publish('ips', 'allowed', data)

    def ip_denied(self, data):
        """
        IP was denied by blacklist
        """
        self._tick('ips_denied')
        self._publish('ips', 'denied', data)

    def asn_allowed(self, data):
        """
        ASN was allowed by whitelist
        """
        self._tick('asns_allowed')
        self._publish('asns', 'allowed', data)

    def asn_denied(self, data):
        """
        ASN was denied by blacklist
        """
        self._tick('asns_denied')
        self._publish('asns', 'denied', data)

    def host_allowed(self, data):
        """
        Host was allowed by whitelist
        """
        self._tick('hosts_allowed')
        self._publish('hosts', 'allowed', data)

    def host_denied(self, data):
        """
        Host was denied by blacklist
        """
        self._tick('hosts_denied')
        self._publish('hosts', 'denied', data)

    def query(self):
        """
        Query counter
        """
        self._tick('total_queries')

    def _tick(self, point):
        """
        Tick a metric
        """
        self.redis.incr('ASNfilter/metrics/' + point)

    def get_metric(self, metric):
        if metric in self.metrics:
            return self.redis.get('ASNfilter/metrics/' + metric)
        else:
            return None

    def get_all(self):
        metrics = {}
        for metric in self.metrics:
            metrics[metric] = self.redis.get('ASNfilter/metrics/' + metric)

        return metrics

    def _publish(self, resource, action, data):
        """
        Publish to Redis
        """
        message = {
            'resource': resource,
            'action': action,
            'data': data
        }

        self.redis.publish('asnfilter-metrics', json.dumps(message))
