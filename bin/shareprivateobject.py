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
class SharePrivateObjectsCommand(GeneratingCommand):

    appname = Option(require=True)
    objtype = Option(require=True)
    objowner = Option(require=True)
    objname = Option(require=True)
    overwrite = Option(require=False)
    clone = Option(require=False)
    reown = Option(require=False)
    newname = Option(require=False)
    newowner = Option(require=False)

    def promote_obj(self, url, auth, owner):
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

    def clone_obj(self, url, obj_name, auth, owner, new_obj_name=None):
        """
          Obtain the current dashboard on a private URL, download the contents of this dashboard 
          Use a POST method to re-create the dashboard at app scope
        """
        attempt = requests.get(url + obj_name + "?output_mode=json", auth=auth, verify=False)
        if attempt.status_code != 200:
            return (False, attempt)

        json_payload = json.loads(attempt.text)['entry'][0]
        orig_name = json_payload['name']
        if new_obj_name:
            name = new_obj_name
        else:
            name = orig_name
        content = json_payload['content']

        #When creating the object we need the name, but this is outside the content section of the JSON data from where we receive all other information
        content['name'] = name

        #Since Splunk has no clone command in the REST API we re-submit the contents of the current object but drop fields that throw errors on creation
        if self.objtype == 'views':
            ignore_list = [ "disabled", "eai:appName", "eai:digest", "eai:userName", "isDashboard", "isVisible", "label", "rootNode", "description" ]
        elif self.objtype == 'extractions':
            ignore_list = [ "attribute" ]
            if orig_name.find(" : REPORT-") != -1:
                content['type'] = 'REPORT'
                index = name.find(" : REPORT-")
            elif orig_name.find(" : EXTRACT-") != -1:
                content['type'] = 'EXTRACT'
                index = name.find(" : EXTRACT-")
            else:
                obj = lambda: None
                obj.status_code = 500
                obj.text = 'Unknown failure, not an extract or report type...had name of %s' % (name)
                return  (False, obj)

            #If we are creating a new object we will not specfiy the name with " : EXTRACT-" or " : REPORT-"
            if not new_obj_name:
                #Splunk adds in the EXTRACT- or REPORT- into the name for us, so remove it from the current name
                content['name'] = content['name'][:index]
        elif self.objtype == 'transforms':
            ignore_list = [ "attribute", "DEFAULT_VALUE", "DEPTH_LIMIT", "LOOKAHEAD", "MATCH_LIMIT", "WRITE_META", "eai:appName", "eai:userName", "DEST_KEY" ]
        elif self.objtype == 'savedsearches':
            ignore_list = [ "embed.enabled", "triggered_alert_count" ]
        else:
            ignore_list = [ ]
         
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
        if self.objtype != 'views' and self.objtype != 'extractions' and self.objtype != 'transforms' and self.objtype != 'savedsearches' and self.objtype != 'macros':
            yield {'result': 'Only objtype=views, objtype=extractions, objtype=savedsearches, objtype=transforms and objtype=macros are supported at this time'}
            return
        
        if self.objtype == 'views':
            obj_endpoint = 'data/ui/views'
            obj_type = 'dashboard'
        elif self.objtype == 'extractions':
            obj_endpoint = 'data/props/extractions'
            obj_type = 'field extraction'
        elif self.objtype == 'transforms':
            obj_endpoint = 'data/transforms/extractions'
            obj_type = 'field transform'
        elif self.objtype == 'savedsearches':
            obj_endpoint = 'saved/searches'
            obj_type = 'saved search'
        elif self.objtype == 'macros':
            obj_endpoint = 'configs/conf-macros'
            obj_type = 'macros'

        #requests library used at this point as we now run as the higher privileged user
        url = 'https://localhost:8089/servicesNS/%s/%s/%s/%s?output_mode=json' % (self.objowner, self.appname, obj_endpoint, self.objname)
        attempt = requests.get(url, verify=False, auth=auth)
        if attempt.status_code != 200:
            yield {'result': 'Unknown failure, received a non-200 response code of %s on the URL %s, text result is %s' % (attempt.status_code, url, attempt.text)}
            return

        #Ok so its not a 404 error so an object exists, but is it private? As this can also show us non-private dashboards
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
            url = 'https://localhost:8089/servicesNS/nobody/%s/%s/%s' % (self.appname, obj_endpoint, self.newname)
        else:
            url = 'https://localhost:8089/servicesNS/nobody/%s/%s/%s' % (self.appname, obj_endpoint, self.objname)
        attempt = requests.get(url, verify=False, auth=auth)

        #404 the object does not exist at app scope already
        if attempt.status_code == 200:
            if self.overwrite is None or self.overwrite != 'true':
                yield {'result': 'The ' + obj_type + ' with name "' + self.objname + '" already exists at app level scope, to overwrite it would require the deletion of the existing object. Use overwrite=true to do this...' }
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

                #delete the old object as requested
                url = 'https://localhost:8089/servicesNS/nobody/%s/%s/%s' % (self.appname, obj_endpoint, obj_name)
                attempt = requests.delete(url, verify=False, auth=auth)
                if attempt.status_code != 200:
                    yield {'result': 'Unknown failure when deleting, received a non-200 response code of %s on the URL %s, text result is %s' % (attempt.status_code, url, attempt.text)}
                    return

                logger.info("user='%s' has removed the app scoped '%s'='%s' in app='%s', clone='%s'" % (username, obj_type, obj_name, self.appname, self.clone))
                url = 'https://localhost:8089/servicesNS/%s/%s/%s/%s/acl' % (self.objowner, self.appname, obj_endpoint, self.objname)
                #If we do not clone we change the existing object to app scope
                if self.clone is None or self.clone == 'false':
                    cloned = False
                    (res, attempt) = self.promote_obj(url, auth, owner)
                elif self.clone == 'true':
                    cloned = True
                    if self.newname:
                        (res, attempt) = self.clone_obj('https://localhost:8089/servicesNS/%s/%s/%s/' % (self.objowner, self.appname, obj_endpoint), self.objname, auth, owner, new_obj_name=self.newname)
                    else:
                        (res, attempt) = self.clone_obj('https://localhost:8089/servicesNS/%s/%s/%s/' % (self.objowner, self.appname, obj_endpoint), self.objname, auth, owner)
                    if res:
                        #Need to ensure that cloned object is now owned by the expected user
                        self.promote_obj('https://localhost:8089/servicesNS/nobody/%s/%s/%s/acl' % (self.appname, obj_endpoint, obj_name), auth, owner)

                if cloned:
                    keyword = "cloned"
                else:
                    keyword = "shared"

                if not res:
                    yield {'result': 'Unknown failure after %s in overwrite mode, received a non-200 response code of %s on the URL %s, text result is %s' % (keyword, attempt.status_code, url, attempt.text)}
                    return
                else:
                    log_str = "user='%s' has action='%s' the '%s'='%s' in app='%s' with new owner='%s' from private_obj_owner='%s'" % (username, keyword, obj_type, self.objname, self.appname, owner, self.objowner)
                    ret_str = 'Old %s removed, replacement %s has been %s with name "%s" in app %s with new owner %s at application level from private object owner %s' % (obj_type, obj_type, keyword, self.objname, self.appname, owner, self.objowner)
                    if self.newname:
                        log_str = log_str + " with new_name='%s'" % (self.newname)
                        ret_str = ret_str + ' with new name of "%s"' % (self.newname)
                    logger.info(log_str)
                    yield {'result': ret_str }
        elif attempt.status_code == 404:
            #If we are not cloning just change the object from private to app scope
            if self.clone is None or self.clone == 'false':
                if self.newname:
                    yield {'result': 'Cannot provide a new name to the object without cloning. Set clone to true and try again'}
                    return
                
                url = 'https://localhost:8089/servicesNS/%s/%s/%s/%s/acl' % (self.objowner, self.appname, obj_endpoint, self.objname)
                (res, attempt) = self.promote_obj(url, auth, owner)
                cloned = False
            elif self.clone == 'true':
                if self.newname:
                    (res, attempt) = self.clone_obj('https://localhost:8089/servicesNS/%s/%s/%s/' % (self.objowner, self.appname, obj_endpoint), self.objname, auth, owner, new_obj_name=self.newname)
                else:
                    (res, attempt) = self.clone_obj('https://localhost:8089/servicesNS/%s/%s/%s/' % (self.objowner, self.appname, obj_endpoint), self.objname, auth, owner)
                cloned = True

                if res:
                    if self.newname:
                        obj_name = self.newname
                    else:
                        obj_name = self.objname
                    #Need to ensure that cloned object is now owned by the expected user
                    self.promote_obj('https://localhost:8089/servicesNS/nobody/%s/%s/%s/acl' % (self.appname, obj_endpoint, obj_name), auth, owner)
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
                log_str = "user='%s' has action='%s' the '%s'='%s' in app='%s' with new owner='%s' from private_obj_owner='%s'" % (username, keyword, obj_type, self.objname, self.appname, owner, self.objowner)
                ret_str = '%s with name "%s" in app %s with owner %s has been %s at application level, new owner is %s' % (obj_type, self.objname, self.objowner, self.appname, keyword, owner)               
                if self.newname:
                    log_str = log_str + " with newname='%s'" % (self.newname)
                    ret_str = ret_str + ' with new name of "%s"' % (self.newname)
                logger.info(log_str)
                yield {'result': ret_str }
        else:
            yield {'result': 'Received the status code of %s with text of %s, unexpected failure' % (attempt.status_code, attempt.text) }

#required for search commands 
dispatch(SharePrivateObjectsCommand, sys.argv, sys.stdin, sys.stdout, __name__)
