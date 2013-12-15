import httplib2
import networkx as nx
import json
import sys
import datetime
import time
import copy
import logging

# This program implements policy based path selection.
# Currently, following options are provided
# Traffic type based - IP TOS/DSCP, Protocol type TCP/UDP
# Time based - Paths keep changing based on time(can be used for WAN links)
# Bandwidth based - can be used to optimally use all paths
# User inputs source and destination nodes, the program calculates all possible 
# paths betweeen source and destination nodes. User can then input the policy
# type and the program will control the path using user selected parameters.
# Tested using Opendaylight and Mininet sample topologies

# Globals
baseUrl = 'http://localhost:8080/controller/nb/v2/'
containerName = 'default/'
ethTypeIp = 0x800
flowCnt = 0
ipTypeTcp = 0x6
ipTypeUdp = 0x11
flowCnt = 0

# Post request
def post_dict(h, url, d):
  resp, content = h.request(
      uri = url,
      method = 'PUT',
      headers={'Content-Type' : 'application/json'},
      body=json.dumps(d)
    )
  return resp, content

# Wrapper function for getall
def get_all_wrapper(typestring, attribute):
    url = baseUrl + typestring
    logging.debug('url %s', url)
    resp, content = h.request(url, "GET")
    allContent = json.loads(content)
    allrows = allContent[attribute]
    return allrows
    
# Builds and returns flow
def build_flow(nodeid, ethertype='', destip='', ipcos='', ipprot='', 
            outnodeconn='', outdstmac=''):
    newflow = {}  
    global flowCnt
    
    flowname = 'flow' + str(flowCnt)
    newflow['name'] = flowname
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
    logging.debug('actions1 %s actions2 %s',actions1, actions2)
    newflow['actions'] = [actions1 + '','' + actions2]
    
    flowCnt += 1
    return newflow, flowname

# Find all hosts connected to the node and add flow entry to reach host from node
def add_flows_host(node_id):
    for host_prop in all_hosts:
        host_node_id = host_prop['nodeId']
        if (host_node_id == node_id):
            node_conn = host_prop['nodeConnectorId']
            dest_ip = host_prop['networkAddress']
            dest_mac = host_prop['dataLayerAddress']
            newflow, flowname = build_flow(nodeid=node_id, outnodeconn=node_conn, 
                ethertype=ethTypeIp, destip=dest_ip, outdstmac=dest_mac)
            post_flow(node_id, newflow, flowname)
    
# Returns all hosts connected to node
def get_allhost_node(node_id):
    host_list=[]
    for host_prop in all_hosts:
        host_node_id = host_prop['nodeId']
        logging.debug('host_node_id %s node_id %s', host_node_id, node_id)
        if (host_node_id == node_id):
            host_list.append(host_prop)
    return host_list

# Returns node connector of source nodeid which has the connection to dest node_id
def find_node_connector(src_node_id, dest_node_id):
    for edge in all_edges:
        if ((src_node_id == edge['edge']['headNodeConnector']['node']['id']) and
            (dest_node_id == edge['edge']['tailNodeConnector']['node']['id'])):
            return (edge['edge']['headNodeConnector']['id'])

# Post flow to controller
def post_flow(nodeid, new_flow, flowname):
    req_str = baseUrl + 'flowprogrammer/default/node/OF/' + nodeid + '/staticFlow/' + flowname
    logging.debug('req_str %s', req_str)
    resp, content = post_dict(h, req_str, new_flow)
    logging.debug('resp %s', resp)
    logging.debug('content %s', content)

# Deletes the specific flow from the node requested
def delete_flow(nodeid, flowname):
    global flowCnt
    req_str = baseUrl + 'flowprogrammer/default/node/OF/' + nodeid + '/staticFlow/' + flowname
    logging.debug('req_str %s', req_str)
    resp, content = h.request(
      uri = req_str,
      method = 'DELETE',
    )
    # Delete flowCnt
    flowCnt -= 1
    return resp, content

# Sets up flow as specified by the path
def setup_path(path):
    # Make copy of path
    path = copy.deepcopy(path)
    
    path_flow_list = []
    path_dict = {}
    path_cnt = len(path)
    src_node_id = path[0]
    dest_node_id = path[path_cnt - 1]
    for iter in range(2):
        if (iter == 0):
            new_dest_node_id = dest_node_id
        else:
            path.reverse()
            new_dest_node_id = src_node_id
        logging.debug('path %s path_cnt %d', path, path_cnt)
        
        for i in range(len(path)):
            if ((i+1) < len(path)):
                nodeid1 = path[i]
                nodeid2 = path[i+1]
                logging.debug('nodeid1 %s nodeid2 %s', nodeid1, nodeid2)
                node_conn = find_node_connector(nodeid1, nodeid2)
                host_list = get_allhost_node(new_dest_node_id)
                
                for host in host_list:
                    ip_addr = host['networkAddress']
                    new_flow, flowname = build_flow(nodeid=nodeid1, outnodeconn=node_conn, 
                                ethertype=ethTypeIp, destip=ip_addr)
                    post_flow(nodeid1, new_flow, flowname)
                    # Build flow list
                    logging.debug('nodeid1 %s flowname %s', nodeid1, flowname)
                    path_dict ={}
                    path_dict['nodeid'] = nodeid1
                    path_dict['flowname'] = flowname
                    path_flow_list.append(path_dict)
        
    return path_flow_list

# Deletes flow corresponding to the flow list passed
def delete_path_flow(path_flow_list):
    for flow in path_flow_list:
        nodeid = flow['nodeid']
        flowname = flow['flowname']
        delete_flow(nodeid, flowname)

# Get node stats
def get_node_stats(nodeid):
    req_str = baseUrl + 'statistics/default/port/node/OF/' + nodeid
    logging.debug('req_str %s', req_str)
    resp, content = h.request(req_str, "GET")
    node_stats = json.loads(content)
    
    return node_stats

# Get node, port stats
def get_port_stats(nodeid, portid):
    node_stats = get_node_stats(nodeid)
    stats = {}
    for stats in node_stats['portStatistic']:
        if (stats['nodeConnector']['id'] == portid):
            logging.info('nodeid %s portid %s txbyte %d rxbyte %d', nodeid, portid, 
            stats['transmitBytes'], stats['receiveBytes'])
            return stats
        
# Calculate bandwidth
def calc_bw(prev_stats, curr_stats, time_int):
    prev_tx_byte_cnt = prev_stats['transmitBytes']
    curr_tx_byte_cnt = curr_stats['transmitBytes']
    prev_rx_byte_cnt = prev_stats['receiveBytes']
    curr_rx_byte_cnt = curr_stats['receiveBytes']
    logging.debug('prev_tx %d curr_tx %d prev_rx %d curr_rx %d', prev_tx_byte_cnt, 
    curr_tx_byte_cnt, prev_rx_byte_cnt, curr_rx_byte_cnt)
    tx_bw = (curr_tx_byte_cnt - prev_tx_byte_cnt)/time_int
    rx_bw = (curr_rx_byte_cnt - prev_rx_byte_cnt)/time_int
    bandwidth = {}
    bandwidth['tx'] = tx_bw
    bandwidth['rx'] = rx_bw
    return bandwidth

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

# Setup credentials for ODL    
h = httplib2.Http(".cache")
h.add_credentials('admin', 'admin')  
    
# Get all hosts, nodes, flows
all_hosts = get_all_wrapper('hosttracker/default/hosts/active/', 'hostConfig')
all_nodes = get_all_wrapper('switchmanager/default/nodes', 'nodeProperties')
all_flows = get_all_wrapper('flowprogrammer/default', 'flowConfig')

# Get all the edges/links
all_edges = get_all_wrapper('topology/default', 'edgeProperties')

# Put nodes and edges into a graph
graph = nx.Graph()
for node in all_nodes:
  graph.add_node(node['node']['id'])
for edge in all_edges:
  e = (edge['edge']['headNodeConnector']['node']['id'], edge['edge']['tailNodeConnector']['node']['id'])
  graph.add_edge(*e)

# Print out graph info as a sanity check
print 'Number of nodes:', graph.number_of_nodes()
print '---- Nodes ----'
print graph.nodes()
print '---- Edges ----'
print graph.edges()

# Find shortest path
src_node_id = raw_input('Enter source node:')
dest_node_id = raw_input('Enter destination node:')
##path = nx.dijkstra_path(graph, src_node, dest_node)
##print 'path', path

# Find all paths
all_paths=[]
all_paths = nx.all_simple_paths(graph, src_node_id, dest_node_id)

# Display all paths
all_path_cnt = 0
all_path_list=[]
for path in all_paths:
    all_path_list.append(path)
    print 'path_cnt', all_path_cnt+1, ':', path
    all_path_cnt += 1
      
# Add flows to reach host
add_flows_host(src_node_id)
add_flows_host(dest_node_id)

print '-----POLICY MENU-----'
print '1. Traffic type'
print '2. Time of day'
print '3. Bandwidth based'
policy_type = raw_input('Enter policy:')

if (policy_type == '1'):
    path_cnt = 1

    print '1. Cos based'
    print '2. TCP/UDP based'
    tr_type = raw_input('Enter traffic type:')

    # Initialize default value
    cos_value = ''
    ip_prot = ''
    for path in all_path_list:
        # Loop through both directions of the path
        for iter in range(2):
            if (iter == 0):
                new_dest_node_id = dest_node_id
            else:
                path.reverse()
                new_dest_node_id = src_node_id
            logging.debug('path %s path_cnt %d', path, path_cnt)
            
            for i in range(len(path)):
                if ((i+1) < len(path)):
                    nodeid1 = path[i]
                    nodeid2 = path[i+1]
                    logging.debug('nodeid1 %s nodeid2 %s', nodeid1, nodeid2)
                    node_conn = find_node_connector(nodeid1, nodeid2)
                    host_list = get_allhost_node(new_dest_node_id)
                    if (tr_type == '1'):
                        if ((path_cnt % 2) == 0):
                            logging.debug('use cos0 for path nodeid1 %s nodeid2 %s', 
                            nodeid1, nodeid2)
                            cos_value = 0
                        else:
                            logging.debug('use cos1 for path nodeid1 %s nodeid2 %s', 
                            nodeid1, nodeid2)
                            cos_value = 1
                    else:
                        if ((path_cnt % 2) == 0):
                            logging.debug('use TCP for path nodeid1 %s nodeid2 %s', 
                            nodeid1, nodeid2)
                            ip_prot = ipTypeTcp
                        else:
                            logging.debug('use UDP for path nodeid1 %s nodeid2 %s', 
                            nodeid1, nodeid2)
                            ip_prot = ipTypeUdp
                    for host in host_list:
                        ip_addr = host['networkAddress']
                        new_flow, flowname = build_flow(nodeid=nodeid1, outnodeconn=node_conn, 
                                    ethertype=ethTypeIp, destip=ip_addr, 
                                    ipcos=cos_value, ipprot=ip_prot)
                        post_flow(nodeid1, new_flow, flowname)
        path_cnt += 1
elif (policy_type == '2'):
    logging.debug('all_path_cnt %d', all_path_cnt)
    if (all_path_cnt < 2):
        print 'Need atleast 2 paths'
        exit()
        
    print 'Time based'
    curr_time = time.time()
    logging.debug('curr_time %d', curr_time)
    # Setup path
    path_cnt = 0
    print 'Setting up path', all_path_list[path_cnt]
    path_flow_list = setup_path(all_path_list[path_cnt])

    while True:
        new_time = time.time()
        # Check if time elapsed is 5 minutes
        if ((new_time - curr_time) > 30):
            # Cleanup old path
            print 'Deleting path', all_path_list[path_cnt]
            delete_path_flow(path_flow_list)
            if ((path_cnt + 1) < all_path_cnt):
                path_cnt = path_cnt + 1
            else:
                path_cnt = 0
            # Setup new path
            print 'Setting up path', all_path_list[path_cnt]
            path_flow_list = setup_path(all_path_list[path_cnt])
            # Reset time
            curr_time = time.time()
        else:
            time.sleep(2)
        
elif (policy_type == '3'):
    print 'Bandwidth based'
    port_stats = {}
    port_stats['nodeid1'] = {}
    port_stats['nodeid1']['nodeconn'] = {}
    # bytes per second
    bw_threshold = 1000
    
    if (all_path_cnt < 2):
        print 'Need atleast 2 paths'
        exit()
        
    # Print primary and backup path
    print 'primary path', all_path_list[0]
    print 'backup path', all_path_list[1]
    
    # Setup primary path
    print 'Setting up path', all_path_list[0]
    path_flow_list = setup_path(all_path_list[0])
    path = all_path_list[0]
    
    loop_cnt = 0
    while True:
        # Monitor primary path
        for i in range(len(path)):
            if ((i+1) < len(path)):
                nodeid1 = path[i]
                nodeid2 = path[i+1]
                logging.debug('nodeid1 %s nodeid2 %s', nodeid1, nodeid2)
                node_conn = find_node_connector(nodeid1, nodeid2)
                port_stats['nodeid1']['nodeconn']['currstats'] = get_port_stats(nodeid1, node_conn)
                # Ignore first reading
                if (loop_cnt > 1):
                    bandwidth = calc_bw(port_stats['nodeid1']['nodeconn']['prevstats'], 
                    port_stats['nodeid1']['nodeconn']['currstats'], 5)
                    logging.debug('bw_tx %d bw_rx %d', bandwidth['tx'], bandwidth['rx'])
                    if ((bandwidth['tx'] > bw_threshold) or (bandwidth['rx'] > bw_threshold)):
                        print 'Switching to backup path', all_path_list[1]
                        delete_path_flow(path_flow_list)
                        setup_path(all_path_list[1])
                        exit()
                # Update prevstats
                port_stats['nodeid1']['nodeconn']['prevstats'] = port_stats['nodeid1']['nodeconn']['currstats']
        loop_cnt += 1
        time.sleep(5)
else:
    print 'Invalid selection'