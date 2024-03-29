import requests
from requests.auth import HTTPBasicAuth
import json

def determine_username(service_obj):
    """
      Provided with the splunklib service object
      Run a get request to determine the username and roles
    """
    res = service_obj.get(path_segment='/services/authentication/current-context', output_mode='json')
    #res['body'] is a response writer but I am unable to determine the nice way to access the body of the data, so str works...
    json_dict = json.loads(res['body'].read().decode("utf-8"))
    username = json_dict['entry'][0]['content']['username']
    roles = json_dict['entry'][0]['content']['roles']
    capabilities = json_dict['entry'][0]['content']['capabilities']

    has_admin = False
    if 'admin_all_objects' in capabilities:
        has_admin = True

    return username, roles, has_admin

def determine_write(service_obj, app_name):
    """
      Provided with the splunklib service object and an application name
      Run a get request to determine if the user running the command has write access to
      the requested app. Return True/False for write access and the username of the current user
    """
    username, roles, has_admin = determine_username(service_obj)
    if has_admin:
        return True, username

    res = service_obj.get(path_segment='/servicesNS/nobody/system/apps/local/' + app_name, output_mode='json')
    json_dict = json.loads(res['body'].read().decode("utf-8"))
    write_roles = json_dict['entry'][0]['acl']['perms']['write']
    has_write = False
    if write_roles[0] == "*":
        has_write = True
    else:
        if set(write_roles) & set(roles):
          has_write = True

    return has_write, username
