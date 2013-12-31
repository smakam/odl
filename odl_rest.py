import httplib2
import json
import sys
import logging

# This is a Python library for common functions accessed using REST api. Applications can 
# import this library and use the following functions.
# build_flow - Returns a key value pair for flow with flow input parameters specified as input
# get_all_hosts_node - Returns all hosts attached to a node as a list
# get_all_flow_stats - Returns list of Flow statistics
# get_all_flows_node - Returns all flows in a node as a list
# get_all_flows - Returns all flows as a list
# get_all_hosts - Returns all hosts as a list
# get_all_containers - Returns all containers as a list
# get_all_nodes - Reutrns all nodes as a list
# get_all_edges - Returns all edges as a list
# get_node_stats - Returns stats for all nodes as a list
# get_node_port_stats - Returns stats for a specific node, port
# delete_all_flows_node - Deletes all flows in a node
# delete_spec_flow_node - Returns a specific flow in a node
# delete_all_flows - Deletes all flows
# 
# There is also a test program below that tests all the library functions.
# Tested using Opendaylight and Mininet sample topologies

# Globals
baseUrl = 'http://localhost:8080/controller/nb/v2'
containerName = 'default/'
ethTypeIp = 0x800
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
    req_str = baseUrl + '/flowprogrammer/default/node/OF/' + nodeid + '/staticFlow/' + flowname
    logging.debug('req_str %s', req_str)
    resp, content = post_dict(h, req_str, new_flow)
    logging.debug('resp %s', resp)
    logging.debug('content %s', content)

# Builds and returns flow
def build_flow(nodeid, flowname, ethertype='', destip='', ipcos='', ipprot='', 
            installflag='', outnodeconn='', outdstmac='', vlan=''):
    newflow = {}
    
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
    if (vlan != ''):
        newflow['vlanId'] = vlan
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
    logging.debug('actions1 %s actions2 %s',actions1, actions2)
    newflow['actions'] = [actions1 + '','' + actions2]
    
    return newflow

def get_all_hosts_node(node_id):
    all_hosts = get_all_hosts()
    host_list=[]
    for host_prop in all_hosts:
        host_node_id = host_prop['nodeId']
        logging.debug('host_node_id %s node_id %s', host_node_id, node_id)
        if (host_node_id == node_id):
            host_list.append(host_prop)
    return host_list

# Get flow stats
def get_all_flow_stats():
    resp, content = h.request('http://127.0.0.1:8080/controller/nb/v2/statistics/default/flow', "GET")
    #print "content ", content
    allFlowStats = json.loads(content)
    flow_stats = allFlowStats['flowStatistics']
    
    return flow_stats
  
# Get all flows in a node
def get_all_flows_node(nodeid):
    url = 'http://localhost:8080/controller/nb/v2/flowprogrammer/default/node/OF/' + nodeid
    logging.debug('url %s', url)
    resp, content = h.request(url, "GET")
    allFlows = json.loads(content)
    flows = allFlows['flowConfig']
    
    return flows
    
# Delete all flows in a node
def delete_all_flows_node(node):
    url = 'http://localhost:8080/controller/nb/v2/flowprogrammer/default/node/OF/' + node
    resp, content = h.request(url, "GET")
    allFlows = json.loads(content)
    flows = allFlows['flowConfig']
    # Dump all flows
    for fs in flows:
        print fs
        # Deleting flows
        flowname = fs['name']
        del_url = url + '/staticFlow/' + flowname
        logging.debug('del_url %s', del_url)
        resp, content = h.request(del_url, "DELETE")
        logging.debug('resp %s content %s', resp, content)

# Delete specific flow specified by nodeid and flowname
def delete_spec_flow_node(node, flowname):
    del_url = 'http://localhost:8080/controller/nb/v2/flowprogrammer/default/node/OF/' + node + '/staticFlow/' + flowname
    logging.debug('del_url %s', del_url)
    resp, content = h.request(del_url, "DELETE")
    logging.debug('resp %s content %s', resp, content)
                
# Delete all flows
def delete_all_flows():
    nodelist = get_all_nodes()
    for node in nodelist:
        nodeid = node['node']['id']
        url = 'http://localhost:8080/controller/nb/v2/flowprogrammer/default/node/OF/' + nodeid
        resp, content = h.request(url, "GET")
        allFlows = json.loads(content)
        flows = allFlows['flowConfig']
        # Delete all flows
        for fs in flows:
            # Deleting flows
            flowname = fs['name']
            del_url = url + '/staticFlow/' + flowname
            logging.debug('del_url %s', del_url)
            resp, content = h.request(del_url, "DELETE")
            logging.debug('resp %s content %s', resp, content)
            

# Wrapper function for getall
def get_all_wrapper(typestring, attribute):
    url = baseUrl + typestring
    logging.debug('url %s', url)
    resp, content = h.request(url, "GET")
    allContent = json.loads(content)
    allrows = allContent[attribute]

    return allrows

# Get all flows
def get_all_flows():
    flow_list = get_all_wrapper('/flowprogrammer/default', 'flowConfig')
    return flow_list

# Get all containers
def get_all_containers():
    cont_list = get_all_wrapper('/containermanager/containers', 'containerConfig')
    return cont_list

# Get list of switches
def get_all_nodes():
    node_list = get_all_wrapper('/switchmanager/default/nodes', 'nodeProperties')
    return node_list
    
# Get all hosts
def get_all_hosts():
    host_list = get_all_wrapper('/hosttracker/default/hosts/active/', 'hostConfig')
    return host_list

# Get all edges
def get_all_edges():
    resp, content = h.request('http://localhost:8080/controller/nb/v2/topology/default', "GET")
    alledges = json.loads(content)
    edges = alledges['edgeProperties']
    
    return edges    
    
# Get node stats
def get_node_stats(nodeid):
    req_str = baseUrl + '/statistics/default/port/node/OF/' + nodeid
    logging.debug('req_str %s', req_str)
    resp, content = h.request(req_str, "GET")
    node_stats = json.loads(content)
    
    return node_stats

# Get node stats for a specific node, port
def get_node_port_stats(nodeid, port):
    node_stats = get_node_stats(nodeid)
    
    for stats in node_stats['portStatistic']:
        if (stats['nodeConnector']['id'] == port):
            return stats
    
    return {}

# START OF MAIN PROGRAM
# Setup logging
LEVELS = {'debug': logging.DEBUG,
          'info': logging.INFO,
          'warning': logging.WARNING,
          'error': logging.ERROR,
          'critical': logging.CRITICAL}

if len(sys.argv) > 1:
    level_name = sys.argv[1]
    level = LEVELS.get(level_name, logging.NOTSET)
    logging.basicConfig(level=level)

h = httplib2.Http(".cache")
h.add_credentials('admin', 'admin')
    
if __name__ == "__main__":
    
    def print_all_nodes():
        node_list = get_all_nodes()
        for node in node_list:
            print node

    def print_all_hosts():
        host_list = get_all_hosts()
        for host in host_list:
            print host
            
    def print_all_flows():
        flow_list = get_all_flows()
        for flow in flow_list:
            print flow
            
    def print_all_flow_stats():
        flow_stats = get_all_flow_stats()
    
        for fs in flow_stats:
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

    def print_all_edges():
        all_edges = get_all_edges()
        for fs in all_edges:
            print fs['edge']['tailNodeConnector']['node']['id'],':',fs['edge']['tailNodeConnector']['id'], 'to', fs['edge']['headNodeConnector']['node']['id'],':',fs['edge']['headNodeConnector']['id']

    def print_all_containers():
        cont_list = get_all_containers()
        for cont in cont_list:
            print cont
            
    def print_all_flows_node():
        nodeid = raw_input('Enter nodeid:')
        flow_list = get_all_flows_node(nodeid)
        # Dump all flows
        for fs in flow_list:
          print fs
    
    def print_all_hosts_node():
        nodeid = raw_input('Enter nodeid:')
        host_list = get_all_hosts_node(nodeid)
        # Dump all hosts
        for fs in host_list:
          print fs
        
    def delete_flows_node():
        nodeid = raw_input('Enter nodeid:')
        delete_all_flows_node(nodeid)
    
    def delete_spec_flow_node():
        nodeid = raw_input('Enter nodeid:')
        flowname = raw_input('Enter flowname:')
        delete_spec_flow_node(nodeid, flowname)
        
    def print_node_stats():
        nodeid = raw_input('Enter nodeid:')
        node_stats = get_node_stats(nodeid)
        
        print '{0:22} {1:5} {2:12} {3:12} {4:12} {5:12}'.format('NODE', 
        'PORT', 'TXPKTCNT', 'TXBYTES', 'RXPKTCOUNT', 'RXBYTES')
        
        for stats in node_stats['portStatistic']:
                print '{0:22} {1:5} {2:10} {3:10} {4:10} {5:10}'.format(node_stats['node']['id'],
                stats['nodeConnector']['id'], stats['transmitPackets'], stats['transmitBytes'], 
                stats['receivePackets'], stats['receiveBytes'])
    
    def print_node_port_stats():
        nodeid = raw_input('Enter nodeid:')
        portid = raw_input('Enter port:')
        node_stats = get_node_port_stats(nodeid, portid)
        
        if (node_stats):
            print '{0:22} {1:5} {2:12} {3:12} {4:12} {5:12}'.format('NODE', 
            'PORT', 'TXPKTCNT', 'TXBYTES', 'RXPKTCOUNT', 'RXBYTES')
            print '{0:22} {1:5} {2:10} {3:10} {4:10} {5:10}'.format(node_stats['nodeConnector']['node']['id'],
            node_stats['nodeConnector']['id'], node_stats['transmitPackets'], node_stats['transmitBytes'], 
            node_stats['receivePackets'], node_stats['receiveBytes'])
                
    def print_all_node_stats():
        node_list = get_all_nodes()
        print '{0:22} {1:5} {2:12} {3:12} {4:12} {5:12}'.format('NODE', 
        'PORT', 'TXPKTCNT', 'TXBYTES', 'RXPKTCOUNT', 'RXBYTES')
        for node in node_list:
            node_stats = get_node_stats(node['node']['id'])
            nodeid = node_stats['node']['id']
            
            for stats in node_stats['portStatistic']:
                print '{0:22} {1:5} {2:10} {3:10} {4:10} {5:10}'.format(node_stats['node']['id'],
                stats['nodeConnector']['id'], stats['transmitPackets'], stats['transmitBytes'], 
                stats['receivePackets'], stats['receiveBytes'])
    
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
        fname='test'
        new_flow = build_flow(nodeid=nodeid, flowname=fname, outnodeconn=nodeconnector, ethertype=ether_type, 
                        installflag = install, destip=dst_ip, outdstmac=dst_mac)
        print 'new_flow', new_flow
        # post the flow to the controller
        post_flow(nodeid, new_flow, fname)

    print '-----REST API LIBRARY MENU-----'
    print '1. Get all switches'
    print '2. Get all hosts'
    print '3. Get all flows'
    print '4. Get all flow stats'
    print '5. Get all Edges in the topology'
    print '6. Get all Containers'
    print '7. Get all node stats'
    print '8. Get node stats in a node'
    print '9. Get port stats'
    print '10. Get hosts attached to a node'
    print '11. Get all flows in a node'
    print '12. Delete all flows in a node'
    print '13. Delete all flows'
    print '14. Delete specific flow in a node'
    print '15. Test flow addition'
    
    option = raw_input('Enter option needed:')

    if (option == '1'):
        print_all_nodes()
    elif (option == '2'):
        print_all_hosts()
    elif (option == '3'):
        print_all_flows()
    elif (option == '4'):
        print_all_flow_stats()    
    elif (option == '5'):
        print_all_edges()
    elif (option == '6'):
        print_all_containers()
    elif (option == '7'):
        print_all_node_stats()
    elif (option == '8'):
        print_node_stats()
    elif (option == '9'):
        print_node_port_stats()
    elif (option == '10'):
        print_all_hosts_node()
    elif (option == '11'):
        print_all_flows_node()
    elif (option == '12'):
        delete_flows_node()
    elif (option == '13'):
        delete_all_flows()
    elif (option == '14'):
        delete_spec_flow_node()
    elif (option == '15'):
        test_flow_add()
    else:
        print 'Invalid option'
