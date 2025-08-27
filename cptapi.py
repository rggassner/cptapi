#! /usr/bin/python3
# -*- coding: utf-8 -*-
import requests
import urllib3
import json
import time
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from typing import Dict, Any, Optional
import ipaddress
import re
requests.packages.urllib3.disable_warnings()

API_WAIT_TIME=.5
PAGE_SIZE=10
HOST_NAME_PREFFIX='host-'
NETWORK_NAME_PREFFIX='network-'

class Cptapi:

    PRIVATE_NETWORKS = [
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('10.0.0.0/8'),
    ]

    DMZ_NETWORKS = [
        ipaddress.ip_network('192.168.0.0/16'),
    ]

    COLOR_INTERNAL = 'blue'
    COLOR_DMZ = 'forest green'
    COLOR_EXTERNAL = 'red'

    def __init__(self,user,password,url,domain,api_wait_time=API_WAIT_TIME,read_only=True,page_size=PAGE_SIZE,publish_wait_time=1,verbose=True):
        self.user=user
        self.password=password
        self.url=url
        self.domain=domain
        self.current_domain = None
        self.original_domain = None
        self.api_wait_time=api_wait_time
        self.page_size=page_size
        self.read_only=read_only
        self.verbose=verbose
        self.sid = self.login(user,password,url,domain,read_only=read_only)
        self.publish_wait_time=publish_wait_time

    def login(self,user,password,url,domain=False,read_only=True,session_comments="Session Comments",session_description="Session Description"):
        payload = {'user':user, 'password' : password, 'session-comments' : session_comments, 'session-description': session_description}
        if domain:
            payload['domain']=domain
        if read_only:
            payload['read-only']=read_only
            del payload['session-comments']
            del payload['session-description']
        response = self.api_call(url, 'login', payload, '')
        if 'sid' in response:
            return response["sid"]
        else:
            message="Login failure. Check username and password. If you are using a demo firewall check if it is still valid."+json.dumps(response)
            quit(message)

    def api_call(self,ap_addr, command, payload, sid):
        url = 'https://' + ap_addr + '/web_api/' + command
        if sid == '':
            request_headers = {'Content-Type' : 'application/json'}
        else:
            request_headers = {'Content-Type' : 'application/json', 'X-chkp-sid' : sid}
        r = self.requests_retry_session().post(url,data=json.dumps(payload), headers=request_headers,verify=False)
        time.sleep(self.api_wait_time)
        #print('api_call command:{}\npayload:{}\nkeys:{}\nrequest:{}\n\n'.format(command,payload,list(r.json().keys()),r.json()))
        return r.json()

    def objects_api_call(self, command, payload, identifications=['objects']):
        payload['limit']=self.page_size
        request_result = self.api_call(self.url,command,payload,self.sid)
        result={}
        for identification in identifications:
            if identification in request_result:
                result[identification]=request_result[identification]
        while 'to' in request_result and 'total' in request_result and request_result['to'] < request_result['total']:
            payload.update({'offset':request_result['to']})
            request_result = self.api_call(self.url,command,payload,self.sid)
            for identification in identifications:
                if identification in request_result:
                    result[identification].extend(request_result[identification])
        return result

    def logout(self):
        command='logout'
        request_data={}
        result=self.api_call(self.url,command,request_data,self.sid)
        return result

    def restore_original_domain(self):
        """Restore the original domain after switching"""
        if self.original_domain and self.original_domain != self.current_domain:
            self.api_call("switch-session", {"target-domain": self.original_domain})
            self.current_domain = self.original_domain  # Switch back to the original domain

    def show_domains(self):
        command='show-domains'
        request_data={}
        result=self.objects_api_call(command,request_data,identifications=['objects'])
        return result['objects']

    def get_host_name(self,ip_address):
        oip = ipaddress.ip_address(str(ip_address))
        if str(oip.version) == '4':
            ip=re.search('([0-9]*)\.([0-9]*)\.([0-9]*)\.([0-9]*)',ip_address)
            if ip:
                found1 = ip.group(1).zfill(3)
                found2 = ip.group(2).zfill(3)
                found3 = ip.group(3).zfill(3)
                found4 = ip.group(4).zfill(3)
                host_name = HOST_NAME_PREFFIX+found1+"-"+found2+"-"+found3+"-"+found4
                return host_name
        if str(oip.version) == '6':
            ipv6 = ipaddress.IPv6Address(ip_address)
            return str(HOST_NAME_PREFFIX)+str(ipv6)

    def get_network_name(self,subnet='',mask_length=''):
        oip = ipaddress.ip_network(str(subnet+'/'+mask_length),strict=False)
        if str(oip.version) == '4':
            ip=re.search('([0-9]*)\.([0-9]*)\.([0-9]*)\.([0-9]*)',str(oip.network_address))
            if ip:
                found1 = ip.group(1).zfill(3)
                found2 = ip.group(2).zfill(3)
                found3 = ip.group(3).zfill(3)
                found4 = ip.group(4).zfill(3)
                network_name = NETWORK_NAME_PREFFIX+found1+"-"+found2+"-"+found3+"-"+found4+"_"+mask_length
                return network_name
        if str(oip.version) == '6':
            ipv6 = ipaddress.IPv6Address(str(oip.network_address))
            return str(NETWORK_NAME_PREFFIX+str(ipv6)+'_'+mask_length)

    def get_object_color(self,fip):
        ip=ipaddress.ip_address(str(fip))
        if any(ip in net for net in self.PRIVATE_NETWORKS):
            return self.COLOR_INTERNAL
        elif any(ip in net for net in self.DMZ_NETWORKS):
            return self.COLOR_DMZ
        else:
            return self.COLOR_EXTERNAL

    def add_host(self,name=False,ipv4_address=False,ip_address=False,ipv6_address=False,comments=False,tags=False,color=False,ignore_warnings=False):
        command='add-host'
        request_data={}
        if ip_address:
            request_data['ip-address']=ip_address
            address=ip_address
        if ipv4_address:
            request_data['ipv4-address']=ipv4_address
            address=ipv4_address
        if ipv6_address:
            request_data['ipv6-address']=ipv6_address
            address=ipv6_address
        if not name :
            name = self.get_host_name(address)
        request_data['name']=name
        if comments:
            request_data['comments']=comments
        if tags:
            request_data['tags']=tags
        if color:
            request_data['color']=color
        else:
            request_data['color']=self.get_object_color(address)
        if ignore_warnings:
            request_data['ignore-warnings']=ignore_warnings
        request_result = self.api_call(self.url, command, request_data ,self.sid)
        if "code" in request_result and request_result["code"] == "err_validation_failed" and self.verbose:
            print(json.dumps(request_result))
        elif "code" in request_result and request_result["code"] == "generic_error" and self.verbose:
            print(json.dumps(request_result))
        else:
            return request_result

    def reassign_all(self):
        if self.verbose:
            print("Reassign domains")
        mds=Cptapi(self.user,self.password,self.url,False,api_wait_time=self.api_wait_time,read_only=False,page_size=self.page_size,publish_wait_time=self.publish_wait_time,verbose=self.verbose)
        for domain in mds.get_domains():
            host_data = {'global-domains':'Global','dependent-domains':domain['name']}
            host_result = mds.api_call(mds.url,'assign-global-assignment',host_data,mds.sid)
            task_id=host_result['tasks'][0]['task-id']
            mds.wait_task_finish(task_id)
            if self.verbose:
                print("Reassigned " + domain['name'])
        return True

    def reinstall_all_policies(self):
        try:
            if self.verbose:
                print("Reassign domains")
            mds=Cptapi(self.user,self.password,self.url,False,api_wait_time=self.api_wait_time,read_only=False,page_size=self.page_size,publish_wait_time=self.publish_wait_time,verbose=self.verbose)
            all_domains = mds.get_domains()  # Assuming this returns a list of domain objects
            for domain in all_domains:
                if self.verbose:
                    print(f"Switching to domain: {domain['name']}...")
                cdomain=Cptapi(self.user,self.password,self.url,domain['name'],api_wait_time=self.api_wait_time,read_only=False,page_size=self.page_size,publish_wait_time=self.publish_wait_time)
                results = cdomain.show_packages()  # Retrieve all policies for the current domain
                for result in results:
                    if result['type'] == "package":
                        cdomain.install_policy(result['name'])
                        if self.verbose:
                            print(f"Policy {result['name']} reinstalled successfully.")
                cdomain.logout()
        except Exception as e:
            if self.verbose:
                print(f"Error while reinstalling policies: {e}")


    def install_policy(self, policy_package=str, targets = None, access=True, threat=True):
        """
        Installs a policy package on the defined targets.
        If 'targets' is None, it uses the ones configured in the package.

        :param policy_package: Name of the policy package to install.
        :param targets: Optional list of targets (names or UIDs). If None, uses targets from the package.
        :param access: Whether to install the Access Control Policy.
        :param threat: Whether to install the Threat Prevention Policy.
        :param comments: Optional comment for the task.
        :return: API response dict.
        """
        payload = {
            "policy-package": policy_package,
            "access": access,
            "threat-prevention": threat,
        }
        if targets:
            payload["targets"] = targets
        return self.api_call(self.url,"install-policy",payload,self.sid)

    def get_domains(self):
        if self.verbose:
            print("Load domains")
        host_data = {'limit':self.page_size}
        host_result = self.api_call(self.url,'show-domains',host_data,self.sid)
        result = host_result['objects']
        return result

    def switch_session(self, domain_uid):
        return self.api_call(self.url,'switch-session',{"uid":domain_uid},self.sid)

    def add_group(self,name=False,comments=False,tags=False,color=False,ignore_warnings=False):
        command='add-group'
        request_data={}
        request_data['name']=name
        if comments:
            request_data['comments']=comments
        if tags:
            request_data['tags']=tags
        if color:
            request_data['color']=color
        if ignore_warnings:
            request_data['ignore-warnings']=ignore_warnings
        request_result = self.api_call(self.url, command, request_data ,self.sid)
        if "code" in request_result and request_result["code"] == "err_validation_failed" and self.verbose:
            print(json.dumps(request_result))
        elif "code" in request_result and request_result["code"] == "generic_error" and self.verbose:
            print(json.dumps(request_result))
        else:
            if self.verbose:
                print(json.dumps(request_result))
            return request_result

    def set_host(self,name=False,ipv4_address=False,ip_address=False,ipv6_address=False,comments=False,tags=False,color=False,ignore_warnings=False):
        command='set-host'
        request_data={}
        if ip_address:
            request_data['ip-address']=ip_address
            address=ip_address
        if ipv4_address:
            request_data['ipv4-address']=ipv4_address
            address=ip4_address
        if ipv6_address:
            request_data['ipv6-address']=ipv6_address
            address=ip6_address
        if not name :
            name = self.get_host_name(address)
        request_data['name']=name
        if comments:
            request_data['comments']=comments
        if tags:
            request_data['tags']=tags
        if color:
            request_data['color']=color
        else:
            request_data['color']=self.get_object_color(address)
        if ignore_warnings:
            request_data['ignore-warnings']=ignore_warnings
        request_result = self.api_call(self.url, command, request_data ,self.sid)
        if "code" in request_result and request_result["code"] == "err_validation_failed" and self.verbose:
            print(json.dumps(request_result))
        elif "code" in request_result and request_result["code"] == "generic_error" and self.verbose:
            print(json.dumps(request_result))
        else:
            return request_result

    def set_group(self,name=False,comments=False,tags=False,color=False,ignore_warnings=False,add=False,remove=False):
        command='set-group'
        request_data={}
        request_data['name']=name
        if comments:
            request_data['comments']=comments
        if tags:
            request_data['tags']=tags
        if color:
            request_data['color']=color
        if ignore_warnings:
            request_data['ignore-warnings']=ignore_warnings
        if add:
            request_data['members']=dict()
            request_data['members']['add']=add
        if remove:
            request_data['members']=dict()
            request_data['members']['remove']=remove
        request_result = self.api_call(self.url, command, request_data ,self.sid)
        if "code" in request_result and request_result["code"] == "err_validation_failed" and self.verbose:
            print(json.dumps(request_result))
        elif "code" in request_result and request_result["code"] == "generic_error" and self.verbose:
            print(json.dumps(request_result))
        else:
            return request_result

#    def set_host_nat_settings(self,name='',nat_settings_install_on='',nat_settings_ipv4_address=''):
#        command='set-host'
#        request_data = {'name':name,'nat-settings':{'install-on':nat_settings_install_on,'hide-behind':'ip-address','ipv4-address':nat_settings_ipv4_address,'auto-rule':True}}
#        request_result = self.api_call(self.url, command, request_data ,self.sid)
#        return request_result
#

    def add_network(self,name=False,subnet='',mask_length='',color=False,comments='',tags=False,ignore_warnings=False):
        oip = ipaddress.ip_network(str(subnet+'/'+mask_length),strict=False)
        subnet=oip.network_address
        subnet=str(subnet)
        command='add-network'
        request_data={}
        request_data['ignore-warnings']=ignore_warnings
        if not name :
            name = self.get_network_name(subnet=subnet,mask_length=mask_length)
        if color:
            request_data['color']=color
        if tags:
            request_data['tags']=tags            
        else:
            request_data['color']=self.get_object_color(subnet)
        request_data['name']=name
        request_data['subnet']=subnet
        request_data['mask-length']=mask_length
        request_data['comments']=comments
        request_result = self.api_call(self.url, command, request_data ,self.sid)
        if "code" in request_result and request_result["code"] == "err_validation_failed" and self.verbose:
            print(json.dumps(request_result))
        elif "code" in request_result and request_result["code"] == "generic_error" and self.verbose:
            print(json.dumps(request_result))
        else:
            return request_result

#    def add_network_to_group(self,network='',group=''):
#        command='set-group'
#        request_data = {'name':group, 'members':{'add':network} }
#        request_result = self.api_call(self.url, command, request_data ,self.sid)
#        if "code" in request_result and request_result["code"] == "err_validation_failed":
#            print(json.dumps(request_result))
#        elif "code" in request_result and request_result["code"] == "generic_error":
#            print(json.dumps(request_result))
#        else:
#            return request_result

    def get_comment(self, uid):
        command="show-object"
        payload = {
            "uid": uid,
            "details-level": "full"
        }
        response=self.api_call(self.url,command,payload,self.sid)
        return response

    def show_session(self):
        command="show-session"
        payload = {}
        response=self.api_call(self.url,command,payload,self.sid)
        return response

    def set_access_rule(self, rule_uid='', layer_uid='',comment=''):
        command="set-access-rule"
        payload = {
            "uid": rule_uid,
            "layer": layer_uid,
            "comments": comment
        }
        response=self.api_call(self.url,command,payload,self.sid)
        return response

    def show_acess_layers(self):
        command='show-access-layers'
        request_data={}
        result=self.objects_api_call(command,request_data,identifications=['access-layers'])
        return result['access-layers']

    def show_access_rulebase(self,name=False,uid=False,dst=False,src=False,packet=False):
        command='show-access-rulebase'
        request_data = {}
        if name:
            request_data['name']=name
        if uid:
            request_data['uid']=uid
        if self.read_only and (src or dst):
            if self.verbose:
                print('Filter is enabled for show access rulebase and connection is on read-only. Change it to read and write.')
            exit()
        if dst:
            request_data['filter']=str('dst:'+dst)
        if src:
            request_data['filter']=str('src:'+src)
        if packet:
            request_data['filter-settings']={}
            request_data['filter-settings']['search-mode']='packet'
        result = self.objects_api_call(command,request_data,identifications=['rulebase','objects-dictionary'])
        return result

    def show_groups(self,gfilter=False,details_level='standard'):
        command='show-groups'
        request_data={}
        request_data['details-level']=details_level
        if gfilter:
            request_data['filter']=gfilter
        result=self.objects_api_call(command,request_data,identifications=['objects'])
        return result['objects']

    def show_hosts(self):
        command='show-hosts'
        request_data={}
        result=self.objects_api_call(command,request_data,identifications=['objects'])
        return result['objects']

    def show_object(self,uid=False):
        command='show-object'
        request_data={}
        if uid:
            request_data['uid']=uid
        result=self.api_call(self.url,command,request_data,self.sid)
        return result['object']

    def show_host(self,ip_address=''):
        command='show-host'
        request_data={}
        request_data['name']=self.get_host_name(ip_address)
        result=self.api_call(self.url,command,request_data,self.sid)
        return result

    def show_group(self,name=''):
        command='show-group'
        request_data={}
        request_data['name']=name
        result=self.api_call(self.url,command,request_data,self.sid)
        return result

    def delete_host(self,name=False):
        command='delete-host'
        request_data={}
        request_data['name']=name
        result=self.api_call(self.url,command,request_data,self.sid)
        return result

    def host_exists(self,ip_address=''):
        command='show-host'
        request_data={}
        request_data['name']=self.get_host_name(ip_address)
        result=self.api_call(self.url,command,request_data,self.sid)
        if 'message' in result and result['message'] == 'Requested object ['+self.get_host_name(ip_address)+'] not found':
            return False
        else:
            return True

    def group_exists(self,name=''):
        command='show-group'
        request_data={}
        request_data['name']=name
        result=self.api_call(self.url,command,request_data,self.sid)
        if 'message' in result and result['message'] == 'Requested object ['+name+'] not found':
            return False
        else:
            return True

    def network_exists(self,subnet='',mask_length=''):
        oip = ipaddress.ip_network(str(subnet+'/'+mask_length),strict=False)
        subnet=oip.network_address
        subnet=str(subnet)
        command='show-network'
        request_data={}
        request_data['name']=self.get_network_name(subnet=subnet,mask_length=mask_length)
        result=self.api_call(self.url,command,request_data,self.sid)
        if 'message' in result and result['message'] == 'Requested object ['+self.get_network_name(subnet=subnet,mask_length=mask_length)+'] not found':
            return False
        else:
            return True

    def show_packages(self):
        command='show-packages'
        request_data={}
        result=self.objects_api_call(command,request_data,identifications=['packages'])
        return result['packages']

    def show_threat_protection(self,uid=False,show_profiles=False):
        command='show-threat-protection'
        request_data={}
        if uid:
            request_data['uid']=uid
        request_data['show-profiles']=show_profiles
        result=self.api_call(self.url, command, request_data ,self.sid)
        return result

    def show_objects(self,object_type=False,ip_only=False,object_filter=False):
        command='show-objects'
        request_data={}
        if object_type:
            request_data['type']=object_type
        request_data['ip-only']=ip_only
        if object_filter:
            request_data['filter']=object_filter
        result=self.objects_api_call(command, request_data,identifications=['objects'])
        return result

    def show_threat_protections(self):
        command='show-threat-protections'
        request_data={}
        result=self.objects_api_call(command, request_data,identifications=['protections'])
        return result['protections']

    def run_ips_update(self):
        command='run-ips-update'
        request_data={}
        result=self.api_call(self.url, command, request_data ,self.sid)
        return result

    def publish(self):
        command='publish'
        request_result = self.api_call(self.url,command,{},self.sid)
        if 'code' in request_result and request_result['code'] == 'err_normalization_failed':
            if self.verbose:
                print('Probably trying to publish in a read-only session.\n{}'.format(request_result))
            return request_result
        task_id=request_result['task-id']
        self.wait_task_finish(task_id)
        return request_result

    def set_threat_protection(self,uid=False,profile=False,action=False,capture_packets=False):
        command='set-threat-protection'
        request_data={}
        overrides={}
        if uid:
            request_data['uid']=uid
        if profile:
            overrides['profile']=profile
        if action:
            overrides['action']=action
        overrides['capture-packets']=capture_packets
        request_data['overrides'] = [overrides]
        #request_data = {'uid':uid, 'overrides':{'profile':profile,'action':action,'capture-packets':capture_packets}}
        request_result = self.api_call(self.url, command, request_data ,self.sid)
        return request_result

#    def set_threat_protection(self,uid='',profile='',action='',capture_packets=''):
#        command='set-threat-protection'
#        request_data = {'uid':uid, 'overrides':{'profile':profile,'action':action,'capture-packets':capture_packets}}
#        request_result = self.api_call(self.url, command, request_data ,self.sid)
#        return request_result
    

    def where_used(self,name='',details_level='standard',indirect=False):
        command='where-used'
        request_data = {'name':name, 'details-level':details_level}
        if indirect:
            request_data['indirect']=indirect
        request_result = self.api_call(self.url, command, request_data ,self.sid)
        return request_result

    def wait_task_finish(self,task_id):
        request_status="in progress"
        request_data = {'task-id':task_id}
        command='show-task'
        while request_status == "in progress":
            time.sleep(self.publish_wait_time)
            request_result = self.api_call(self.url,command,request_data,self.sid)
            request_status = request_result['tasks'][0]['status']
        return request_result

    def requests_retry_session(
        retries=5,
        backoff_factor=0.3,
        status_forcelist=(500, 502, 504),
        session=None,
        ):
        session = session or requests.Session()
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session
