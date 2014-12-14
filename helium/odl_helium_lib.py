import httplib2
import json
import sys
import logging

# Globals
baseUrl = 'http://localhost:8181/restconf'
allSwitch = []
allEdges = []

# Wrapper function for getall
def get_wrapper(typestring):
    url = baseUrl + typestring
    logging.debug('url %s', url)
    resp, content = h.request(url, "GET")
    all_content = json.loads(content)

    return all_content

# Parse node inventory
def parse_node():
    node_content = get_wrapper('/operational/opendaylight-inventory:nodes/')
    node_list = node_content['nodes']['node']
    
    for node in node_list:
        switch = {}
        switch['id'] = node['id']
        switch['nodeconn'] = []
        switch['flow'] = []
        node_conn_list = node['node-connector']

       # Get flows
        flow_table = node['flow-node-inventory:table']
        for flow in flow_table:
            if 'flow-hash-id-map' in flow:
                flow_sub_table = flow['flow']
                for sub_flow in flow_sub_table: 
                    flow_info = {}
                    flow_info['id'] = sub_flow['id']
                    flow_info['match'] = sub_flow['match']
                    flow_info['pkts'] = sub_flow['opendaylight-flow-statistics:flow-statistics']['packet-count']
                    flow_info['bytes'] = sub_flow['opendaylight-flow-statistics:flow-statistics']['byte-count']
                    if 'instructions' in sub_flow:
                         flow_info['action'] = sub_flow['instructions']
                    switch['flow'].append(flow_info)
            
        for conn in node_conn_list:
            node_conn = {}
            node_conn['id'] = conn['id']

            # Get node connector stats
            conn_stats = conn['opendaylight-port-statistics:flow-capable-node-connector-statistics']
            stats = {}
            stats['txpkt'] = conn_stats['packets']['transmitted']
            stats['txbytes'] = conn_stats['bytes']['transmitted']
            stats['rxpkt'] = conn_stats['packets']['received']
            stats['rxbytes'] = conn_stats['bytes']['received']
            node_conn['stats'] = stats

            # Get hosts attached
            node_conn['hosts'] = []
            if 'address-tracker:addresses' in conn:
                hlist = conn['address-tracker:addresses']
                for host in hlist:
                    host_info = {}
                    host_info['id'] = host['id']
                    host_info['mac'] = host['mac']
                    host_info['ip'] = host['ip']
                    node_conn['hosts'].append(host_info)
            

            switch['nodeconn'].append(node_conn)
        allSwitch.append(switch)    

# Parse topology
def parse_topology():
    top_content = get_wrapper('/operational/network-topology:network-topology/')
    edge_list = (top_content['network-topology']['topology'])[0]['link']

    for edge in edge_list:
        edge_info = {}
        edge_info['id'] = edge['link-id']
        edge_info['src_node'] = edge['source']['source-node']
        edge_info['src_node_conn'] = edge['source']['source-tp']
        edge_info['dst_node'] = edge['destination']['dest-node']
        edge_info['dst_node_conn'] = edge['destination']['dest-tp']
        
        allEdges.append(edge_info)

def get_all_nodes():
    return allSwitch

def get_all_edges():
    return allEdges
    
# MAIN    
h = httplib2.Http(".cache")
h.add_credentials('admin', 'admin')

# Parse node inventory and topology
parse_node()
parse_topology()

if __name__ == "__main__":    
    
    # Test functions
    for switch in allSwitch:
        print switch
    
    for edge in allEdges:
        print edge