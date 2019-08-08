#!/usr/bin/env python
from __future__ import absolute_import, division, print_function, unicode_literals
import sys
import os
import json
import utility
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option
from splunklib.binding import HTTPError

@Configuration(type='reporting')
class ListDispatchTTLCommand(GeneratingCommand):

    appname = Option(require=True)
    savedsearch = Option(require=True)
    owner = Option(require=False)
    sharing = Option(require=False)

    def generate(self):
        """
          The logic is:
            List the dispatch.ttl value of a savedsearch
            If the optional sharing level is not specified use the user context to see the saved search 
            If the owner is specified look under the particular owner/user context, only someone with admin access can use this option
        """
        (username, roles) = utility.determine_username(self.service)

        if self.sharing is not None and self.sharing != 'user':
            context = 'nobody'
        else:
            if self.owner is not None:
                context = self.owner
            else:
                context = username

        url = 'https://localhost:8089/servicesNS/%s/%s/' % (context, self.appname)
        url = url + 'saved/searches/' + self.savedsearch + '?output_mode=json'

        headers = { 'Authorization': 'Splunk ' + self._metadata.searchinfo.session_key }
        attempt = requests.get(url, verify=False, headers=headers)
        if attempt.status_code != 200:
            yield {'result': 'Unknown failure, received a non-200 response code of %s on the URL %s, text result is %s' % (attempt.status_code, url, attempt.text)}
            return
             
        entry = json.loads(attempt.text)['entry'][0]
        ttl = entry['content']['dispatch.ttl']
        acl = entry['acl']
        obj_sharing = acl['sharing']
        obj_owner = acl['owner']
        obj_app = acl['app']

        yield {'result': 'For saved search %s from app %s with owner %s, sharing level of %s TTL is %s' % (self.savedsearch, obj_app, obj_owner, obj_sharing, ttl) }

dispatch(ListDispatchTTLCommand, sys.argv, sys.stdin, sys.stdout, __name__)
