#!/usr/bin/env python
from __future__ import absolute_import, division, print_function, unicode_literals
import sys
import os
import json
import requests
from requests.auth import HTTPBasicAuth
import utility

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option

@Configuration(type='reporting')
class ListPrivateObjectsCommand(GeneratingCommand):

    appname = Option(require=True)
    objtype = Option(require=True)
    objowner = Option(require=False)

    def generate(self):
        """
          The logic is:
            If the user has write access to the requested app then:
            List the private objects within the app as statistics in Splunk
            The objowner parameter is optional and narrows down to a particular user's private objects
          Currently only views (dashboards), extractions and transforms are supported
        """

        (has_write, username) = utility.determine_write(self.service, self.appname)
         
        if not has_write:
           yield {'result': 'You do not have write access to the application "%s".\nYou cannot list the private objects within this app, please contact an app admin for the requested app' % self.appname}
           return

        if self.objowner is None:
            self.objowner = "-"

        if self.objtype != "views" and self.objtype != 'extractions' and self.objtype != 'transforms':
            yield {'result': 'Only objtype=views, objtype=extractions, objtype=transforms are supported at this time'}
            return

        url = 'https://localhost:8089/servicesNS/%s/%s/directory' % (self.objowner, self.appname)
 
        if self.objtype == 'views':
            url = url + '?search=eai:location%3D/data/ui/views'
        elif self.objtype == 'extractions':
            url = url + '?search=eai:location%3D/data/props/extractions'
        elif self.objtype == 'transforms':
            url = url + '?search=eai:location%3D/data/transforms/extractions'

        url = url + '&search=eai:acl.app%3D' + self.appname + '&count=0&output_mode=json'
        
        #Hardcoded user credentials
        attempt = requests.get(url, verify=False, auth=HTTPBasicAuth('admin', 'changeme'))
        if attempt.status_code != 200:
            yield {'result': 'Unknown failure, received a non-200 response code of %s on the URL %s, text result is %s' % (attempt.status_code, url, attempt.text)}
            return
            
        #We received a response but it could be a globally shared object and not one from this app so we now need to check
        all_found_objects = json.loads(attempt.text)['entry']
        #Only list the objects that are private
        objects = {object['name']: object['acl']['owner'] for object in all_found_objects if object['acl']['sharing'] == 'user'}
        for object_name in objects:
            yield { 'result': object_name, 'owner': objects[object_name] }

dispatch(ListPrivateObjectsCommand, sys.argv, sys.stdin, sys.stdout, __name__)
