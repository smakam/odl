# Config for switches, tunnelIP is the local IP address.
switches = [{'name': 's1',
             'tunnelIp': '192.168.56.104',
             'dpid': '1'},
            {'name': 's2',
             'tunnelIp': '192.168.56.102',
             'dpid': '2'}]

defaultContainerImage='alagalah/odlpoc_ovs230'

#Note that tenant name and endpointGroup name come from policy_config.py

hosts = [          {'name': 'h35_2',
          'mac': '00:00:00:00:35:02',
          'ip': '10.0.35.2/24',
          'switch': 's1',
          'tenant': 'GBPPOC',
	  'container_image': 'smakam/apachedocker',
          'endpointGroup': 'client1'},
         {'name': 'h35_3',
          'ip': '10.0.35.3/24',
          'mac': '00:00:00:00:35:03',
          'switch': 's1',
          'tenant': 'GBPPOC',
	  'container_image': 'smakam/apachedocker',
          'endpointGroup': 'client1'},
         {'name': 'h36_2',
          'ip': '10.0.36.2/24',
          'mac': '00:00:00:00:36:02',
          'switch': 's1',
          'tenant': 'GBPPOC',
	  'container_image': 'smakam/postgresdocker',
          'endpointGroup': 'dbserver'},
         {'name': 'h36_3',
          'ip': '10.0.36.3/24',
          'mac': '00:00:00:00:36:03',
          'switch': 's1',
          'tenant': 'GBPPOC',
	  'container_image': 'smakam/postgresdocker',
          'endpointGroup': 'dbserver'},
         {'name': 'h37_2',
          'ip': '10.0.37.2/24',
          'mac': '00:00:00:00:37:02',
          'switch': 's1',
          'tenant': 'GBPPOC',
	  'container_image': 'smakam/apachedocker',
          'endpointGroup': 'client2'},
         {'name': 'h37_3',
          'ip': '10.0.37.3/24',
          'mac': '00:00:00:00:37:03',
          'switch': 's1',
          'tenant': 'GBPPOC',
	  'container_image': 'smakam/apachedocker',
          'endpointGroup': 'client2'},
          {'name': 'h35_4',
          'mac': '00:00:00:00:35:04',
          'ip': '10.0.35.4/24',
          'switch': 's2',
          'tenant': 'GBPPOC',
	  'container_image': 'smakam/apachedocker',
          'endpointGroup': 'client1'},
         {'name': 'h35_5',
          'ip': '10.0.35.5/24',
          'mac': '00:00:00:00:35:05',
          'switch': 's2',
          'tenant': 'GBPPOC',
	  'container_image': 'smakam/apachedocker',
          'endpointGroup': 'client1'},
         {'name': 'h36_4',
          'ip': '10.0.36.4/24',
          'mac': '00:00:00:00:36:04',
          'switch': 's2',
          'tenant': 'GBPPOC',
	  'container_image': 'smakam/postgresdocker',
          'endpointGroup': 'dbserver'},
         {'name': 'h36_5',
          'ip': '10.0.36.5/24',
          'mac': '00:00:00:00:36:05',
          'switch': 's2',
          'tenant': 'GBPPOC',
	  'container_image': 'smakam/postgresdocker',
          'endpointGroup': 'dbserver'},
         {'name': 'h37_4',
          'ip': '10.0.37.4/24',
          'mac': '00:00:00:00:37:04',
          'switch': 's2',
          'tenant': 'GBPPOC',
	  'container_image': 'smakam/apachedocker',
          'endpointGroup': 'client2'},
         {'name': 'h37_5',
          'ip': '10.0.37.5/24',
          'mac': '00:00:00:00:37:05',
          'switch': 's2',
          'tenant': 'GBPPOC',
	  'container_image': 'smakam/apachedocker',
          'endpointGroup': 'client2'}
	]
