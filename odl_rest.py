import httplib2
import json

# This program contains test functions to invoke REST apis from different bundles available
# in Opendaylight. Eventual goal is to make this as library so that higher layer apps can 
# reuse the library.
# Tested using Opendaylight and Mininet sample topologies

# Globals
baseUrl = 'http://localhost:8080/controller/nb/v2/'
containerName = 'default/'
ethTypeIp = 0x800
flowCnt = 0
ipTypeTcp = 0x6
ipTypeUdp = 0x11

# Parse actionstr 
def parse_action(actions):
  action_str = ''
  for act in actions:
    actionType = act['type']
    if actionType == 'OUTPUT':
      action_str += '(' + 'TYPE:' + actionType + ' NODE:' + act['port']['node']['id'] + ',PORT:' + act['port']['id'] + ')'
    elif actionType == 'SET_DL_DST':
      action_str += '(' + 'TYPE:' + actionType + ' ADDRESS:' + act['address'] + ')'
  return action_str

# Parse matchstr
def parse_match(match_field):
    match_str = ''
    for match in match_field:
        match_type = match['type']
        match_str += '(' + 'TYPE:' + match_type + ' VALUE:' + match['value'] + ' )'
    
    return match_str

# Post request
def post_dict(h, url, d):
  resp, content = h.request(
      uri = url,
      method = 'PUT',
      headers={'Content-Type' : 'application/json'},
      body=json.dumps(d)
    )
  return resp, content

# Post flow to controller
def post_flow(nodeid, new_flow, flowname):
    req_str = baseUrl + 'flowprogrammer/default/node/OF/' + nodeid + '/staticFlow/' + flowname
    print 'req_str', req_str
    resp, content = post_dict(h, req_str, new_flow)
    print 'resp', resp
    print 'content', content

# Builds and returns flow
def build_flow(nodeid, ethertype='', destip='', ipcos='', ipprot='', 
            installflag='', outnodeconn='', outdstmac=''):
    newflow = {}
    
    global flowCnt
    flowname = 'flow' + str(flowCnt)
    newflow['name'] = flowname
    if (installflag != ''):
        newflow['installInHw'] = installflag
    else:
        newflow['installInHw'] = 'true'
    newflow['node'] = {u'id': nodeid, u'type': u'OF'}
    if (destip != ''):
        newflow['nwDst'] = destip
    if (ethertype != ''):
        newflow['etherType'] = ethertype
    if (ipcos != ''):
        newflow['tosBits'] = ipcos
    if (ipprot != ''):
        newflow['protocol'] = ipprot
    newflow['priority']=500
    node = {}
    node['id'] = nodeid
    node['type'] = 'OF'
    newflow['node'] = node
    
    actions1 = 'OUTPUT='+str(outnodeconn)
    if (outdstmac != ''):
        actions2 = 'SET_DL_DST='+str(outdstmac)
    else:
        actions2 = ''
    print 'actions1',actions1,'actions2',actions2
    newflow['actions'] = [actions1 + '','' + actions2]
    
    flowCnt += 1
    return newflow, flowname

# Get flow stats
def get_flow_stats():
    resp, content = h.request('http://127.0.0.1:8080/controller/nb/v2/statistics/default/flow', "GET")
    #print "content ", content
    allFlowStats = json.loads(content)
    #print "allflowstats ", allFlowStats
    flowStats = allFlowStats['flowStatistics']
    flowcnt = 0
    
    for fs in flowStats:
      print "\nSwitch ID : " + fs['node']['id']
      print '{0:15} {1:15} {2:5} {3:5}'.format('MATCH', 'ACTION', 'PKCOUNT', 'BYTECOUNT')

      for aFlow in fs['flowStatistic']:
        pkt_count = aFlow['packetCount']
        byte_count = aFlow['byteCount']
        actions = aFlow['flow']['actions']
        action_str = parse_action(actions)
        matchfield = aFlow['flow']['match']['matchField']
        match_str = parse_match(matchfield)
        
        print '{0:15} {1:15} {2:5} {3:5}'.format(match_str, action_str, pkt_count, byte_count)

# Get all flows in a node
def get_all_flows_node():
    node = raw_input('Enter nodeid:')
    url = 'http://localhost:8080/controller/nb/v2/flowprogrammer/default/node/OF/' + node
    resp, content = h.request(url, "GET")
    allFlows = json.loads(content)
    flows = allFlows['flowConfig']
    # Dump all flows
    flowcnt = 0
    for fs in flows:
      print fs
      flowcnt = flowcnt + 1

# Delete all flows in a node
def delete_all_flows_node():
    node = raw_input('Enter nodeid:')
    url = 'http://localhost:8080/controller/nb/v2/flowprogrammer/default/node/OF/' + node
    resp, content = h.request(url, "GET")
    allFlows = json.loads(content)
    flows = allFlows['flowConfig']
    # Dump all flows
    flowcnt = 0
    for fs in flows:
        print fs
        # Deleting flows
        flowname = fs['name']
        del_url = url + '/staticFlow/' + flowname
        print 'del_url', del_url
        resp, content = h.request(del_url, "DELETE")
        print 'resp', resp, 'content', content
        flowcnt = flowcnt + 1

# Delete all flows
def delete_all_flows():
    nodelist = get_all_switches()
    for node in nodelist:
        nodeid = node['node']['id']
        url = 'http://localhost:8080/controller/nb/v2/flowprogrammer/default/node/OF/' + nodeid
        resp, content = h.request(url, "GET")
        allFlows = json.loads(content)
        flows = allFlows['flowConfig']
        # Dump all flows
        flowcnt = 0
        for fs in flows:
            print fs
            # Deleting flows
            flowname = fs['name']
            del_url = url + '/staticFlow/' + flowname
            print 'del_url', del_url
            resp, content = h.request(del_url, "DELETE")
            print 'resp', resp, 'content', content
            flowcnt = flowcnt + 1
            
# Test flow addition 
def test_flow_add():
    install_flag = raw_input('Enter install flag:')
    if (install_flag == '1'):
        install = 'true'
    else:
        install = 'false'
    nodeid='00:00:00:00:00:00:00:01'
    nodeconnector=3
    ether_type=0x800
    dst_mac='00:00:00:00:00:01'
    dst_ip='10.0.1.1'
    new_flow, flowname = build_flow(nodeid=nodeid, outnodeconn=nodeconnector, ethertype=ether_type, 
                    installflag = install, destip=dst_ip, outdstmac=dst_mac)
    print 'new_flow', new_flow
    # post the flow to the controller
    post_flow(nodeid, new_flow, flowname)


# Wrapper function for getall
def get_all_wrapper(typestring, attribute):
    url = 'http://localhost:8080/controller/nb/v2' + typestring
    print 'url', url
    resp, content = h.request(url, "GET")
    allContent = json.loads(content)
    allrows = allContent[attribute]
    # Dump all content
    rowcnt = 0
    for fs in allrows:
      print fs
      rowcnt = rowcnt + 1
    
    return allrows
    
# Get all flows
def get_all_flows():
    get_all_wrapper('/flowprogrammer/default', 'flowConfig')

# Get all containers
def get_all_containers():
    get_all_wrapper('/containermanager/containers', 'containerConfig')

# Get list of switches
def get_all_switches():
    all_nodes = get_all_wrapper('/switchmanager/default/nodes', 'nodeProperties')
    return all_nodes
    
# Get all hosts
def get_all_hosts():
    get_all_wrapper('/hosttracker/default/hosts/active/', 'hostConfig')

# Get all edges
def get_all_edges():
    resp, content = h.request('http://localhost:8080/controller/nb/v2/topology/default', "GET")
    alledges = json.loads(content)
    edges = alledges['edgeProperties']
    edgecnt = 0
    for fs in edges:
        print fs['edge']['tailNodeConnector']['node']['id'],':',fs['edge']['tailNodeConnector']['id'], 
        'to', fs['edge']['tailNodeConnector']['node']['id'],':',fs['edge']['headNodeConnector']['id']
        edgecnt = edgecnt + 1
    
# Get node stats
def get_node_stats(nodeid):
    req_str = baseUrl + 'statistics/default/port/node/OF/' + nodeid
    #print 'req_str', req_str
    resp, content = h.request(req_str, "GET")
    node_stats = json.loads(content)
    
    return node_stats
    
# Get all node stats
def get_all_node_stats():
    # Get all nodes
    node_list = get_all_switches()
    print '{0:22} {1:5} {2:12} {3:12} {4:12} {5:12}'.format('NODE', 
    'PORT', 'TXPKTCNT', 'TXBYTES', 'RXPKTCOUNT', 'RXBYTES')
    for node in node_list:
        node_stats = get_node_stats(node['node']['id'])
        nodeid = node_stats['node']['id']
        
        for stats in node_stats['portStatistic']:
            print '{0:22} {1:5} {2:10} {3:10} {4:10} {5:10}'.format(node_stats['node']['id'],
            stats['nodeConnector']['id'], stats['transmitPackets'], stats['transmitBytes'], 
            stats['receivePackets'], stats['receiveBytes'])
    
h = httplib2.Http(".cache")
h.add_credentials('admin', 'admin')

print '-----REST API LIBRARY MENU-----'
print '1. Get all switches'
print '2. Get all hosts'
print '3. Get flows'
print '4. Get flow stats'
print '5. Get all Edges in the topology'
print '6. Get all Containers'
print '7. get all flows in a node'
print '8. Delete all flows in a node'
print '9. Delete all flows'
print '10. Test flow addition'
print '11. Get node stats'
option = raw_input('Enter option needed:')

if (option == '1'):
    get_all_switches()
elif (option == '2'):
    get_all_hosts()
elif (option == '3'):
    get_all_flows()
elif (option == '4'):
    get_flow_stats()    
elif (option == '5'):
    get_all_edges()
elif (option == '6'):
    get_all_containers()
elif (option == '7'):
    get_all_flows_node()
elif (option == '8'):
    delete_all_flows_node()
elif (option == '9'):
    delete_all_flows()
elif (option == '10'):
    test_flow_add()
elif (option == '11'):
    get_all_node_stats()
else:
    print 'Invalid option'

### Get specific static flow
##resp, content = h.request('http://localhost:8080/controller/nb/v2/flowprogrammer/default/node/OF/00:00:00:00:00:00:00:03/staticFlow/testflow', "GET")
##print 'resp', resp
##allFlows = json.loads(content)
##print 'specific flow1:', allFlows

# Delete specific static flow
##resp, content = h.request('http://localhost:8080/controller/nb/v2/flowprogrammer/default/node/OF/00:00:00:00:00:00:00:03/staticFlow/testflow', "DELETE")
##print 'resp', resp
##
### Get specific static flow
##resp, content = h.request('http://localhost:8080/controller/nb/v2/flowprogrammer/default/node/OF/00:00:00:00:00:00:00:03/staticFlow/testflow', "GET")
##print 'resp', resp
##allFlows = json.loads(content)
##print 'specific flow3:', allFlows