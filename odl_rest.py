import httplib2
import json

# This program contains test functions to invoke REST apis from different bundles available
# in Opendaylight. Eventual goal is to make this as library so that higher layer apps can 
# reuse the library.
# Tested using Opendaylight and Mininet sample topologies

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
    
# Get all flows
def get_all_flows():
    get_all_wrapper('/flowprogrammer/default', 'flowConfig')

# Get all containers
def get_all_containers():
    get_all_wrapper('/containermanager/containers', 'containerConfig')

# Get list of switches
def get_all_switches():
    get_all_wrapper('/switchmanager/default/nodes', 'nodeProperties')
    
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