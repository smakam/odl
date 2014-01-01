import httplib2
import json
import sys
import logging
from odllib import *

# This program is a prototype for a switch that can Mux/Demux packets based on incoming
# vlan of the packet. The user can input vlan corresponding to individual host and the switch
# will dynamically add reactive flows based on the user input. Practical usecase of this is 
# for the scenario where a single test equipment port is available to the user and the user 
# wants to test multiple Devices using a single test port.
# Tested using Opendaylight and Mininet, traffic generation using Packeth

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

# Get list of hosts
all_hosts = get_all_hosts()

# Get all edges
all_edges = get_all_edges()
for fs in all_edges:
    print fs['edge']['tailNodeConnector']['node']['id'],':',fs['edge']['tailNodeConnector']['id'], 'to', fs['edge']['headNodeConnector']['node']['id'],':',fs['edge']['headNodeConnector']['id']
    
in_node_conn = raw_input('Enter source port:')        
hostid = 0
for hosts in all_hosts:
    # get Node associated with this host
    nodeid1 = hosts['nodeId']
    nodeconnector = hosts['nodeConnectorId']
    
    # Get user input for vlan associated with the host
    print 'host address is', hosts['networkAddress'], 'connected to node', nodeid1
    vlanid = raw_input('Enter vlan for the above host:')
    print 'vlan: ', vlanid

    # Build flow for demux
    fname = 'flow' + str(hostid)
      
    newFlow = build_flow(nodeid=nodeid1, flowname=fname, outnodeconn=nodeconnector, vlan=vlanid)
    logging.debug('newFlow', newFlow)

    # post the flow to the controller
    post_flow(nodeid1, newFlow, fname)
    
    # Build flow for mux
    fname = 'flowx' + str(hostid)
    newFlow = build_flow(nodeid=nodeid1, flowname=fname, innodeconn=nodeconnector, vlan=vlanid, 
        outnodeconn=in_node_conn)
    logging.debug('newFlow', newFlow)
    
    # post the flow to the controller
    post_flow(nodeid1, newFlow, fname)
    
    hostid+=1