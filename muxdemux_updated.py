import httplib2
import json
import sys

# This program is a prototype for a switch that can Mux/Demux packets based on incoming
# vlan of the packet. The user can input vlan corresponding to individual host and the switch
# will dynamically add reactive flows based on the user input. Practical usecase of this is 
# for the scenario where a single test equipment port is available to the user and the user 
# wants to test multiple Devices using a single test port.
# Tested using Opendaylight and Mininet, traffic generation using Packeth

def post_dict(h, url, d):
  resp, content = h.request(
      uri = url,
      method = 'PUT',
      headers={'Content-Type' : 'application/json'},
      body=json.dumps(d)
    )
  
  return resp, content

def build_flow(flowname, nodeid, nodeconnectorid, vlan):
    newflow = {u'actions': [u'OUTPUT='+nodeconnectorid],
        u'etherType': u'0x8100',
        u'installInHw': u'true',
        u'name': flowname,
        u'vlanId':vlan,
        u'node': {u'id': nodeid, u'type': u'OF'},
        u'priority': u'500'}
    return newflow
  
    
h = httplib2.Http(".cache")
h.add_credentials('admin', 'admin')

# Get list of hosts
resp, content = h.request('http://localhost:8080/controller/nb/v2/hosttracker/default/hosts/active', "GET")
all_hosts = json.loads(content)
all_hosts = all_hosts['hostConfig']

for hosts in all_hosts:
    nodeid = hosts['nodeId']
hostid = 0
for hosts in all_hosts:
    # get Node associated with this host
    nodeid = hosts['nodeId']
    nodeconnector = hosts['nodeConnectorId']
    
    # Get user input for vlan associated with the host
    print 'host address is', hosts['networkAddress'], 'connected to node', nodeid
    vlan = raw_input('Enter vlan for the above host:')
    print 'vlan: ', vlan

    # Build flow    
    flowname = 'flow' + str(hostid);
    req_str = 'http://localhost:8080/controller/nb/v2/flowprogrammer/default/node/OF/' + nodeid + '/staticFlow/' + flowname
  
    newFlow = build_flow(flowname, nodeid, nodeconnector, vlan)
    print 'newFlow', newFlow

    # post the flow to the controller
    resp, content = post_dict(h, req_str, newFlow)
    print 'content', content
    hostid+=1

#Add host
##req_str = 'http://localhost:8080/controller/nb/v2/hosttracker/default/address/10.0.0.3'
##flowtest = {
## "dataLayerAddress":"00:00:00:01:01:01",
## "nodeType":"OF",
## "nodeId":"00:00:00:00:00:00:00:03",
## "nodeConnectorType":"OF",
## "nodeConnectorId":"1",
## "vlan":"10",
## "staticHost":"true",
## "networkAddress":"10.0.0.3"
##}
##print 'flowtest', flowtest
##resp, content = post_dict(h, req_str, flowtest)
##print 'resp ', resp
##print 'content', content

