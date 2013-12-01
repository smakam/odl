/*
 * Copyright (c) 2013 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

/*
 * vlans are hardcoded currently
 */
package org.opendaylight.controller.muxdemuxapp.internal;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.opendaylight.controller.hosttracker.IfIptoHost;
import org.opendaylight.controller.hosttracker.IfNewHostNotify;
import org.opendaylight.controller.hosttracker.hostAware.HostNodeConnector;
import org.opendaylight.controller.sal.action.Action;
import org.opendaylight.controller.sal.action.Output;
import org.opendaylight.controller.sal.core.Host;
import org.opendaylight.controller.sal.core.Node;
import org.opendaylight.controller.sal.core.NodeConnector;
import org.opendaylight.controller.sal.flowprogrammer.Flow;
import org.opendaylight.controller.sal.flowprogrammer.IFlowProgrammerService;
import org.opendaylight.controller.sal.match.Match;
import org.opendaylight.controller.sal.match.MatchField;
import org.opendaylight.controller.sal.match.MatchType;
import org.opendaylight.controller.sal.packet.Ethernet;
import org.opendaylight.controller.sal.packet.IDataPacketService;
import org.opendaylight.controller.sal.packet.IEEE8021Q;
import org.opendaylight.controller.sal.packet.IListenDataPacket;
import org.opendaylight.controller.sal.packet.Packet;
import org.opendaylight.controller.sal.packet.PacketResult;
import org.opendaylight.controller.sal.packet.RawPacket;
import org.opendaylight.controller.sal.utils.Status;
import org.opendaylight.controller.switchmanager.ISwitchManager;
import org.opendaylight.controller.topologymanager.ITopologyManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MuxDemuxApp implements IListenDataPacket, IfNewHostNotify {
    private static final Logger logger = LoggerFactory
            .getLogger(MuxDemuxApp.class);
    private ISwitchManager switchManager = null;
    private ITopologyManager topologyManager = null;
    private IFlowProgrammerService programmer = null;
    private IDataPacketService dataPacketService = null;
    private IfIptoHost hostTracker;
    private final Map<Node, Map<Long, NodeConnector>> mac_to_port_per_switch = new HashMap<Node, Map<Long, NodeConnector>>();
    private final String function = "hub";

    void setDataPacketService(IDataPacketService s) {
        this.dataPacketService = s;
    }

    void unsetDataPacketService(IDataPacketService s) {
        if (this.dataPacketService == s) {
            this.dataPacketService = null;
        }
    }

    public ITopologyManager getTopologyManager() {
        return topologyManager;
    }

    public void setTopologyManager(ITopologyManager topologyManager) {
        logger.debug("Setting topologyManager");
        this.topologyManager = topologyManager;
    }

    public void unsetTopologyManager(ITopologyManager topologyManager) {
        if (this.topologyManager == topologyManager) {
            this.topologyManager = null;
        }
    }

    public void setHostTracker(IfIptoHost hostTracker) {
        logger.debug("Setting HostTracker");
        this.hostTracker = hostTracker;
    }

    public void unsetHostTracker(IfIptoHost hostTracker) {
        if (this.hostTracker == hostTracker) {
            this.hostTracker = null;
        }
    }

    public void setFlowProgrammerService(IFlowProgrammerService s) {
        this.programmer = s;
    }

    public void unsetFlowProgrammerService(IFlowProgrammerService s) {
        if (this.programmer == s) {
            this.programmer = null;
        }
    }

    void setSwitchManager(ISwitchManager s) {
        logger.debug("SwitchManager set");
        this.switchManager = s;
    }

    void unsetSwitchManager(ISwitchManager s) {
        if (this.switchManager == s) {
            logger.debug("SwitchManager removed!");
            this.switchManager = null;
        }
    }

    /**
     * Function called by the dependency manager when all the required
     * dependencies are satisfied
     *
     */
    void init() {
        logger.info("Initialized");
    }

    /**
     * Function called by the dependency manager when at least one dependency
     * become unsatisfied or when the component is shutting down because for
     * example bundle is being stopped.
     *
     */
    void destroy() {
    }

    /**
     * Function called by dependency manager after "init ()" is called and after
     * the services provided by the class are registered in the service registry
     *
     */
    void start() {
        logger.info("Started");
    }

    /**
     * Function called by the dependency manager before the services exported by
     * the component are unregistered, this will be followed by a "destroy ()"
     * calls
     *
     */
    void stop() {
        logger.info("Stopped");
    }

    @Override
    public PacketResult receiveDataPacket(RawPacket inPkt) {
        if (inPkt == null) {
            return PacketResult.IGNORED;
        }

        Packet formattedPak = this.dataPacketService.decodeDataPacket(inPkt);
        NodeConnector incoming_connector = inPkt.getIncomingNodeConnector();
        Node incoming_node = incoming_connector.getNode();

        logger.info("Received2 frame of size: {} from node {} connect {}",
                inPkt.getPacketData().length, incoming_node, incoming_connector);

        if (formattedPak instanceof Ethernet) {
            byte[] srcMAC = ((Ethernet) formattedPak).getSourceMACAddress();
            byte[] dstMAC = ((Ethernet) formattedPak)
                    .getDestinationMACAddress();

            Packet nextPak = formattedPak.getPayload();
            if (nextPak instanceof IEEE8021Q) {
                short vid = ((IEEE8021Q) nextPak).getVid();
                /*
                 * if vid==10, send to host1
                 * if vid==20, send to host2
                 * default, send to host1
                 */
                // Get node list
                Set<Node> nodeList = this.switchManager.getNodes();
                for (Node n : nodeList) {
                    //logger.info("node {}", n);
                }

                // Get host list
                try {
                    Set<HostNodeConnector> allHosts = this.hostTracker.getAllHosts();
                    for (HostNodeConnector host : allHosts) {
                        logger.info("hostnode {}", host);
                    }
                } catch (Exception e3) {
                    // TODO Auto-generated catch block
                    e3.printStackTrace();
                }


                /* Get nodeconnector set from incoming node */
                Set<NodeConnector> nodeConnectors = this.switchManager
                        .getUpNodeConnectors(incoming_node);

                /* Based on incoming vid in the packet, set the ip address field */
                InetAddress ip_address = null;
                byte[] ipAddr;
                try {
                    switch (vid) {

                    case 10:
                        ipAddr = new byte[]{10, 0, 0, 1};
                        ip_address = InetAddress.getByAddress(ipAddr);
                        break;
                    case 20:
                        ipAddr = new byte[]{10, 0, 0, 2};
                        ip_address = InetAddress.getByAddress(ipAddr);
                        break;
                    default:
                        ipAddr = new byte[]{10, 0, 0, 1};
                        ip_address = InetAddress.getByAddress(ipAddr);
                        break;

                    }
                } catch (UnknownHostException e1) {
                    // TODO Auto-generated catch block
                    e1.printStackTrace();
                }

                /* From list of nodeconnectors, find the nodeconnector which has the host ip that
                 * matches with the ip determined from incoming packet's vid. Send packet to that host.
                 */

                for (NodeConnector p : nodeConnectors) {
                    logger.info("Nodeconnector {}", p);
                    try {
                        List<Host> hostList = topologyManager.getHostsAttachedToNodeConnector(p);
                        if (hostList != null) {
                            for (int i=0; i<hostList.size(); i++) {
                                Host hostEntry = hostList.get(i);
                                logger.info("Nodeconnector {} Host {} ip_address {}", p, hostEntry, ip_address);

                                if (hostEntry.getNetworkAddress().equals(ip_address)) {
                                    logger.info("Found host {} nodeconnector {}", hostEntry, p);
                                    RawPacket destPkt = new RawPacket(inPkt);
                                    destPkt.setOutgoingNodeConnector(p);
                                    this.dataPacketService.transmitDataPacket(destPkt);

                                    /* Add flow */
                                    Match match = new Match();
                                    match.setField(new MatchField(MatchType.DL_VLAN, vid));

                                    List<Action> actions = new ArrayList<Action>();
                                    actions.add(new Output(p));

                                    Flow f = new Flow(match, actions);

                                    // Modify the flow on the network node
                                    Status status = programmer.addFlow(incoming_node, f);
                                    if (!status.isSuccess()) {
                                        logger.warn(
                                                "SDN Plugin failed to program the flow: {}. The failure is: {}",
                                                f, status.getDescription());
                                        return PacketResult.IGNORED;
                                    }
                                    logger.info("Installed flow {} in node {}", f,
                                            incoming_node);
                                }
                            }
                        } else{
                            logger.info("host list is null");
                        }
                    } catch (Exception e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }

            } else {
                logger.trace("Not 8021q");
            }

        }
        return PacketResult.IGNORED;
    }

    @Override
    public void notifyHTClient(HostNodeConnector host) {
        logger.info("Host {} added", host);
    }

    @Override
    public void notifyHTClientHostRemoved(HostNodeConnector host) {
        logger.info("Host {} removed", host);
    }
}
