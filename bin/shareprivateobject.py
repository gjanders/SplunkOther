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

import logging
import splunk
def setup_logging():
    """
     setup_logging as found on http://dev.splunk.com/view/logging/SP-CAAAFCN
    """
    logger = logging.getLogger('splunk.shareprivateobjects')
    SPLUNK_HOME = os.environ['SPLUNK_HOME']
    
    LOGGING_DEFAULT_CONFIG_FILE = os.path.join(SPLUNK_HOME, 'etc', 'log.cfg')
    LOGGING_LOCAL_CONFIG_FILE = os.path.join(SPLUNK_HOME, 'etc', 'log-local.cfg')
    LOGGING_STANZA_NAME = 'python'
    LOGGING_FILE_NAME = "shareprivateobjects.log"
    BASE_LOG_PATH = os.path.join('var', 'log', 'splunk')
    LOGGING_FORMAT = "%(asctime)s %(levelname)-s\t %(message)s"
    splunk_log_handler = logging.handlers.RotatingFileHandler(os.path.join(SPLUNK_HOME, BASE_LOG_PATH, LOGGING_FILE_NAME), mode='a') 
    splunk_log_handler.setFormatter(logging.Formatter(LOGGING_FORMAT))
    logger.addHandler(splunk_log_handler)
    splunk.setupSplunkLogger(logger, LOGGING_DEFAULT_CONFIG_FILE, LOGGING_LOCAL_CONFIG_FILE, LOGGING_STANZA_NAME)
    return logger
logger = setup_logging()

@Configuration(type='reporting')
class ListPrivateObjectsCommand(GeneratingCommand):

    appname = Option(require=True)
    objtype = Option(require=True)
    objowner = Option(require=True)
    objname = Option(require=True)
    overwrite = Option(require=False)
    clone = Option(require=False)
    reown = Option(require=False)
    newname = Option(require=False)
    newowner = Option(require=False)

    def promote_dashboard(self, url, auth, owner):
        """
          Change sharing to app level, change owner as requested
          Return True for success, False for failure, with the requests result
        """
        data = { 'sharing': 'app', 'owner': owner }
        attempt = requests.post(url, auth=auth, data=data, verify=False)
        if attempt.status_code != 200:
            return (False, attempt)
        else:
            return (True, attempt)

    def clone_dashboard(self, url, obj_name, auth, owner, new_obj_name=None):
        """
          Obtain the current dashboard on a private URL, download the contents of this dashboard 
          Use a POST method to re-create the dashboard at app scope
        """
        attempt = requests.get(url + obj_name + "?output_mode=json", auth=auth, verify=False)
        if attempt.status_code != 200:
            return (False, attempt)

        json_payload = json.loads(attempt.text)['entry'][0]
        if new_obj_name:
            name = new_obj_name
        else:
            name = json_payload['name']
        content = json_payload['content']

        #When creating the dashboard we need the name, but this is outside the content section of the JSON data from where we receive all other information
        content['name'] = name

        #Since Splunk has no clone command in the REST API we re-submit the contents of the current dashboard but drop fields that throw errors on creation
        ignore_list = [ "disabled", "eai:appName", "eai:digest", "eai:userName", "isDashboard", "isVisible", "label", "rootNode", "description" ]

        for ignore_item in ignore_list:
            if ignore_item in content:
                del content[ignore_item]
        
        #switch to app context before posting the dashboard
        new_url = url.replace('servicesNS/' + self.objowner,'servicesNS/nobody')
        attempt = requests.post(new_url, auth=auth, data=content, verify=False)
        if attempt.status_code != 200 and attempt.status_code!=201:
            return (False, attempt)
        else:
            return (True, attempt)

    def generate(self):
        """
          This method generates the search statistics
          The logic is:
            * If the user does not have write access to the app in question do nothing (return with an error)
            * If the object type is not "views" return an error as only views are supported
            * If the object cannot be found return an error
            * If the object exists at app scope and the overwrite option is not true, return an error
            * Based on the above either change the object from private scope to app scope, or clone the object by creating a new object
              at app scope
            * If overwrite=true then if the object exists at app scope it is deleted first
            * If reown=true then the owner of the app scoped object is changed to the user calling this command
        """
        if len(self.objowner)<4:
            yield {'result': 'Object owner name shorter than 4 characters. objowner of %s is unlikely to be a valid object owner, returning' % (self.objowner) }
        
        (has_write, username) = utility.determine_write(self.service, self.appname)
         
        if not has_write:
           yield {'result': 'You do not have write access to the application "%s".\nYou cannot list the private objects within this app, please contact an app admin for the requested app' % self.appname}
           return

        #Hardcoded user credentials here
        auth = HTTPBasicAuth('admin', 'changeme')
        if self.objtype != "views":
            yield {'result': 'Only objtype=views supported at this time'}
            return
        
        #requests library used at this point as we now run as the higher privileged user
        url = 'https://localhost:8089/servicesNS/%s/%s/data/ui/views/%s?output_mode=json' % (self.objowner, self.appname, self.objname)
        attempt = requests.get(url, verify=False, auth=auth)
        if attempt.status_code != 200:
            yield {'result': 'Unknown failure, received a non-200 response code of %s on the URL %s, text result is %s' % (attempt.status_code, url, attempt.text)}
            return

        #Ok so its not a 404 error so a dashboard exists, but is it private? As this can also show us non-private dashboards
        #we should only ever receive 1 result when looking in the user context, unless the objowner is -
        acl = json.loads(attempt.text)['entry'][0]['acl']
        sharing = acl['sharing']
        owner = acl['owner']

        #It is possible to see non-private objects in this scope owned by other users so first check the owner of the object
        if self.objowner != owner:
            yield {'result': 'Unable to find private dashboard with the name of %s in app %s owner of %s, url %s was used' % (self.objname, self.appname, self.objowner, url) }
            return

        #Did we see an object that is user scope and not an app scoped object?
        if sharing != 'user':
            yield {'result': 'Sharing level on url %s was found to be %s, this command only works on private objects' % (url, sharing) }
            return

        #Set the owner to leave the app scoped objet owned by one we finish
        if self.reown is None or self.reown == "false":
            owner = self.objowner
        elif self.reown == "true":
            owner = username
            if self.newowner:
                app_name = __file__.split(os.sep)[-3]
                res = self.service.get("/servicesNS/nobody/%s/storage/collections/data/shareprivateobject_owners" % (app_name))
                json_dict = json.loads(str(res['body']))
                username_list = [ entry.get('username') for entry in json_dict ]
                if set(username_list) & set([self.newowner]):
                    owner = self.newowner
                else:
                    yield {'result': 'New owner was requested to be "%s" but this owner is not in the list of valid users to own modified objects. List is "%s"' % (self.newowner, username_list)}
                    return
        else:
            yield {'result': 'reown must be set to true or false'}
            return
        
        if self.newname:
            url = 'https://localhost:8089/servicesNS/nobody/%s/data/ui/views/%s' % (self.appname, self.newname)
        else:
            url = 'https://localhost:8089/servicesNS/nobody/%s/data/ui/views/%s' % (self.appname, self.objname)
        attempt = requests.get(url, verify=False, auth=auth)

        #404 the object does not exist at app scope already
        if attempt.status_code == 200:
            if self.overwrite is None or self.overwrite != 'true':
                yield {'result': 'The dashboard already exists at app level scope, to overwrite it would require the deletion of the existing object. Use overwrite=true to do this...' }
                return

            if self.overwrite == 'true':
                if self.clone is not None and self.clone != 'false' and self.clone != 'true':
                    yield {'result': 'clone must be set to true or false'}
                    return
                
                if self.newname and (self.clone is None or self.clone != 'true'):
                    yield {'result': 'Cannot provide a new name to the object without cloning. Set clone to true and try again'}
                    return
                
                if self.newname:
                    obj_name = self.newname
                else:
                    obj_name = self.objname

                #delete the old dashboard as requested
                url = 'https://localhost:8089/servicesNS/nobody/%s/data/ui/views/%s' % (self.appname, obj_name)
                attempt = requests.delete(url, verify=False, auth=auth)
                if attempt.status_code != 200:
                    yield {'result': 'Unknown failure when deleting, received a non-200 response code of %s on the URL %s, text result is %s' % (attempt.status_code, url, attempt.text)}
                    return

                logger.info("user='%s' has removed the app scoped dashboard='%s' in app='%s', clone='%s'" % (username, obj_name, self.appname, self.clone))
                url = 'https://localhost:8089/servicesNS/%s/%s/data/ui/views/%s/acl' % (self.objowner, self.appname, self.objname)
                #If we do not clone we change the existing dashboard to app scope
                if self.clone is None or self.clone == 'false':
                    cloned = False
                    (res, attempt) = self.promote_dashboard(url, auth, owner)
                elif self.clone == 'true':
                    cloned = True
                    if self.newname:
                        (res, attempt) = self.clone_dashboard('https://localhost:8089/servicesNS/%s/%s/data/ui/views/' % (self.objowner, self.appname), self.objname, auth, owner, new_obj_name=self.newname)
                    else:
                        (res, attempt) = self.clone_dashboard('https://localhost:8089/servicesNS/%s/%s/data/ui/views/' % (self.objowner, self.appname), self.objname, auth, owner)
                    if res:
                        #Need to ensure that cloned dashboard is now owned by the expected user
                        self.promote_dashboard('https://localhost:8089/servicesNS/nobody/%s/data/ui/views/%s/acl' % (self.appname, obj_name), auth, owner)

                if cloned:
                    keyword = "cloned"
                else:
                    keyword = "shared"

                if not res:
                    yield {'result': 'Unknown failure after %s in overwrite mode, received a non-200 response code of %s on the URL %s, text result is %s' % (keyword, attempt.status_code, url, attempt.text)}
                    return
                else:
                    log_str = "user='%s' has action='%s' the dashboard='%s' in app='%s' with new owner='%s' from private_obj_owner='%s'" % (username, keyword, self.objname, self.appname, owner, self.objowner)
                    ret_str = 'Old dashboard removed, replacement dashboard has been %s with name %s in app %s with new owner %s at application level from private object owner %s' % (keyword, self.objname, self.appname, owner, self.objowner)
                    if self.newname:
                        log_str = log_str + " with new_name='%s'" % (self.newname)
                        ret_str = ret_str + ' with new name is %s' % (self.newname)
                    logger.info(log_str)
                    yield {'result': ret_str }
        elif attempt.status_code == 404:
            #If we are not cloning just change the dashboard from private to app scope
            if self.clone is None or self.clone == 'false':
                if self.newname:
                    yield {'result': 'Cannot provide a new name to the object without cloning. Set clone to true and try again'}
                    return
                
                url = 'https://localhost:8089/servicesNS/%s/%s/data/ui/views/%s/acl' % (self.objowner, self.appname, self.objname)
                (res, attempt) = self.promote_dashboard(url, auth, owner)
                cloned = False
            elif self.clone == 'true':
                if self.newname:
                    (res, attempt) = self.clone_dashboard('https://localhost:8089/servicesNS/%s/%s/data/ui/views/' % (self.objowner, self.appname), self.objname, auth, owner, new_obj_name=self.newname)
                else:
                    (res, attempt) = self.clone_dashboard('https://localhost:8089/servicesNS/%s/%s/data/ui/views/' % (self.objowner, self.appname), self.objname, auth, owner)
                cloned = True

                if res:
                    if self.newname:
                        obj_name = self.newname
                    else:
                        obj_name = self.objname
                    #Need to ensure that cloned dashboard is now owned by the expected user
                    self.promote_dashboard('https://localhost:8089/servicesNS/nobody/%s/data/ui/views/%s/acl' % (self.appname, obj_name), auth, owner)
            else:
                yield {'result': 'clone must be set to true or false'}
                return

            if cloned:
                keyword = "cloned"
            else:
                keyword = "shared"

            if not res:
                yield {'result': 'Unknown failure after %s in non-overwrite mode, received a non-200 response code of %s on the URL %s, text result is %s' % (keyword, attempt.status_code, url, attempt.text)}
                return
            else:
                log_str = "user='%s' has action='%s' the dashboard='%s' in app='%s' with new owner='%s' from private_obj_owner='%s'" % (username, keyword, self.objname, self.appname, owner, self.objowner)
                ret_str = 'Dashboard %s in app %s with owner %s has been %s at application level, new owner is %s' % (self.objname, self.appname, self.objowner, keyword, owner)               
                if self.newname:
                    log_str = log_str + " with newname='%s'" % (self.newname)
                    ret_str = ret_str + ' with new name as %s' % (self.newname)
                logger.info(log_str)
                yield {'result': ret_str }
        else:
            yield {'result': 'Received the status code of %s with text of %s, unexpected failure' % (attempt.status_code, attempt.text) }

#required for search commands 
dispatch(ListPrivateObjectsCommand, sys.argv, sys.stdin, sys.stdout, __name__)
