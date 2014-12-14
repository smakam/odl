import sys
from odl_helium_lib import *

node_list = get_all_nodes()
edge_list = get_all_edges()
    
def print_all_nodes():
    for node in node_list:
        print node['id']

def print_node_stats():
    for node in node_list:
        print 'NODE:', node['id']
        node_conn_list = node['nodeconn']
        print '{0:12} {1:10} {2:10} {3:10} {4:10}'.format(
            'PORT', 'TXPKTCNT', 'TXBYTES', 'RXPKTCOUNT', 'RXBYTES')
        for conn in node_conn_list:
            print '{0:12} {1:10} {2:10} {3:10} {4:10}'.format(conn['id'], \
                conn['stats']['txpkt'], conn['stats']['txbytes'], \
                conn['stats']['rxpkt'], conn['stats']['rxbytes'])
                
def print_all_hosts():
    for node in node_list:
        print '{0:12} {1:10} {2:10} {3:10}'.format(
            'PORT', 'HOSTID', 'HOSTMAC', 'HOSTIP')
        print 'NODE:', node['id']
        node_conn_list = node['nodeconn']
        for conn in node_conn_list:
            host_list = conn['hosts']

            for host in host_list:
                print '{0:12} {1:10} {2:10} {3:10}'.format(
                conn['id'], host['id'], host['mac'], host['ip'])

def print_all_flows():
    print '{0:12} {1:10} {2:10} {3:10} {4:10}'.format(
        'FLOWID', 'MATCH', 'ACTION', 'PKTCOUNT', 'BYTECOUNT')
    for node in node_list:
        print 'NODE:', node['id']
        flow_list = node['flow']
        for flow in flow_list:
            if 'action' in flow:
                print flow['id'], flow['match'], flow['action'], flow['pkts'], flow['bytes']

def print_all_edges():
    for edge in edge_list:
        print edge['src_node_conn'], 'to', edge['dst_node_conn']
        
while True:
    print '-----REST API LIBRARY MENU-----'
    print '0: Exit'
    print '1. Get all switches'
    print '2. Get all hosts'
    print '3. Get all flows'
    print '4. Get all Edges in the topology'
    print '5. Get all node stats'
    print '6. Delete all flows in a node'
    print '7. Delete all flows'

    option = raw_input('Enter option needed:')

    if (option == '0'):
        exit()
    if (option == '1'):
        print_all_nodes()
    elif (option == '2'):
        print_all_hosts()
    elif (option == '3'):
        print_all_flows()  
    elif (option == '4'):
        print_all_edges()
    elif (option == '5'):
        print_node_stats()
    elif (option == '6'):
        delete_flows_node()
    elif (option == '7'):
        delete_all_flows()
    else:
        print 'Invalid option'
