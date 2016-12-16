##Library Header
# $Id: $
# Copyright © 2003-2007 by IXIA
# All Rights Reserved.
#
# Name:
#    ixia_lacp_api.tcl
#
# Purpose:
#     A script development library containing LACP APIs for test automation
#     with the Ixia chassis.
#
# Author:
#    Lavinia Raicea
#
# Usage:
#    package require Ixia
#
# Description:
#    The procedures contained within this library include:
#
#    - emulation_lacp_link_config
#    - emulation_lacp_control
#    - emulation_lacp_info
#
# Requirements:
#     ixiaapiutils.tcl , a library containing TCL utilities
#     parseddashedargs.tcl , a library containing the proceDescr and
#     parsedashedargds.tcl.
#
# Variables:
#
# Keywords:
#
# Category:
#
################################################################################
#                                                                              #
#                                LEGAL  NOTICE:                                #
#                                ==============                                #
# The following code and documentation (hereinafter "the script") is an        #
# example script for demonstration purposes only.                              #
# The script is not a standard commercial product offered by Ixia and have     #
# been developed and is being provided for use only as indicated herein. The   #
# script [and all modifications, enhancements and updates thereto (whether     #
# made by Ixia and/or by the user and/or by a third party)] shall at all times #
# remain the property of Ixia.                                                 #
#                                                                              #
# Ixia does not warrant (i) that the functions contained in the script will    #
# meet the user's requirements or (ii) that the script will be without         #
# omissions or error-free.                                                     #
# THE SCRIPT IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, AND IXIA        #
# DISCLAIMS ALL WARRANTIES, EXPRESS, IMPLIED, STATUTORY OR OTHERWISE,          #
# INCLUDING BUT NOT LIMITED TO ANY WARRANTY OF MERCHANTABILITY AND FITNESS FOR #
# A PARTICULAR PURPOSE OR OF NON-INFRINGEMENT.                                 #
# THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SCRIPT  IS WITH THE #
# USER.                                                                        #
# IN NO EVENT SHALL IXIA BE LIABLE FOR ANY DAMAGES RESULTING FROM OR ARISING   #
# OUT OF THE USE OF, OR THE INABILITY TO USE THE SCRIPT OR ANY PART THEREOF,   #
# INCLUDING BUT NOT LIMITED TO ANY LOST PROFITS, LOST BUSINESS, LOST OR        #
# DAMAGED DATA OR SOFTWARE OR ANY INDIRECT, INCIDENTAL, PUNITIVE OR            #
# CONSEQUENTIAL DAMAGES, EVEN IF IXIA HAS BEEN ADVISED OF THE POSSIBILITY OF   #
# SUCH DAMAGES IN ADVANCE.                                                     #
# Ixia will not be required to provide any software maintenance or support     #
# services of any kind (e.g., any error corrections) in connection with the    #
# script or any part thereof. The user acknowledges that although Ixia may     #
# from time to time and in its sole discretion provide maintenance or support  #
# services for the script, any such services are subject to the warranty and   #
# damages limitations set forth herein and will not obligate Ixia to provide   #
# any additional maintenance or support services.                              #
#                                                                              #
################################################################################

#Note: 
# This file is derived from the original ixia_lacp_api.tcl
# Modified in order to support LACP configuration using IxTclNetwork API

# Copyright © 2014 Intel Corp
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Intel Corp license agreement.

##Procedure Header
# Name:
#    ::ixia::emulation_lacp_link_config
#
# Description:
#    This command is used to create/modify/delete/enable/disable a LACP link.
#
# Synopsis:
#    ::ixia::emulation_lacp_link_config
#        [-actor_key                        RANGE 0-65535 DEFAULT 1]
#        [-actor_key_step                   RANGE 0-65535 DEFAULT 1]
#        [-actor_port_num                   RANGE 0-65535 DEFAULT 1]
#        [-actor_port_num_step              RANGE 0-65535 DEFAULT 1]
#        [-actor_port_pri                   RANGE 0-65535 DEFAULT 1]
#        [-actor_port_pri_step              RANGE 0-65535 DEFAULT 1]
#        [-actor_system_id                  MAC DEFAULT 0000.0000.0001]
#        [-actor_system_id_step             MAC DEFAULT 0000.0000.0001]
#        [-actor_system_pri                 RANGE 0-65535 DEFAULT 1]
#        [-actor_system_pri_step            RANGE 0-65535 DEFAULT 1]
#        [-aggregation_flag                 CHOICES auto disable DEFAULT auto]
#        [-auto_pick_port_mac               CHOICES 0 1 DEFAULT 1]
#        [-collecting_flag                  CHOICES 0 1 DEFAULT 1]
#        [-collector_max_delay              RANGE 0-65535 DEFAULT 0]
#        [-distributing_flag                CHOICES 0 1 DEFAULT 1]
#        [-handle]
#        [-inter_marker_pdu_delay           RANGE 1-255 DEFAULT 6]
#        [-lacp_activity                    CHOICES active passive DEFAULT active]
#        [-lacp_timeout                     CHOICES short long auto RANGE 1-65535 DEFAULT auto]
#        [-lacpdu_periodic_time_interval    CHOICES fast slow auto RANGE 1-65535 DEFAULT auto]
#        [-lag_count                        NUMERIC DEFAULT 1]
#        [-marker_req_mode                  CHOICES fixed random DEFAULT fixed]
#        [-marker_res_wait_time             RANGE 1-255 DEFAULT 5]
#        [-mode                             CHOICES create modify enable disable delete DEFAULT create]
#        [-no_write]
#        [-port_handle                      REGEXP ^[0-9]+/[0-9]+/[0-9]+$
#        [-port_mac                         MAC DEFAULT 0000.0000.0001]
#        [-port_mac_step                    MAC DEFAULT 0000.0000.0001]
#        [-reset]
#        [-send_marker_req_on_lag_change    CHOICES 0 1 DEFAULT 1]
#        [-send_periodic_marker_req         CHOICES 0 1 DEFAULT 0]
#        [-support_responding_to_marker     CHOICES 0 1 DEFAULT 1]
#        [-sync_flag                        CHOICES auto disable DEFAULT auto]
#
# Arguments:
#
#   -actor_key
#        The operational Key value assigned to the port by the Actor. 
#        Minimum value is 0. 
#        Maximum value is 65535. 
#        This parameter is optional. 
#        In order for a port to be grouped in the same LAG with other ports, 
#        the actor key must be the same for all ports.
#        This parameter is valid only when -mode is create/modify.
#        (DEFAULT = 1)
#   -actor_key_step
#        The incrementing step for the operational Key value assigned to the 
#        port by the Actor. 
#        Minimum value is 0. 
#        Maximum value is 65535. 
#        This parameter is optional. 
#        In order for a port to be grouped in the same LAG with other ports, 
#        the actor key must be the same for all ports.
#        This parameter is valid only when -mode is create and -count is 
#        greater than 1.
#        (DEFAULT = 1)
#   -actor_port_num
#        The port number assigned to the port by the Actor (the System sending 
#        the PDU). 
#        Minimum value is 0. 
#        Maximum value is 65535. 
#        This parameter is optional. 
#        This parameter is valid only when -mode is create/modify.
#        (DEFAULT = 1)
#   -actor_port_num_step
#        The incrementing step for the port number assigned to the port by 
#        the Actor (the System sending the PDU). 
#        Minimum value is 0. 
#        Maximum value is 65535. 
#        This parameter is optional.
#        (DEFAULT = 1)
#        This parameter is valid only when -mode is create and -count is 
#        greater than 1.
#   -actor_port_pri
#        This field specifies the port priority of the link Actor. 
#        Minimum value is 0. 
#        Maximum value is 65535. 
#        This parameter is optional. 
#        This parameter is valid only when -mode is create/modify.
#        (DEFAULT = 1)
#   -actor_port_pri_step
#        The incrementing step for the port priority of the link Actor. 
#        Minimum value is 0. 
#        Maximum value is 65535. 
#        This parameter is optional. 
#        This parameter is valid only when -mode is create and -count is 
#        greater than 1.
#        (DEFAULT = 1)
#   -actor_system_id
#        The system ID identifies an LACP system for negotiation with other 
#        LACP systems. The switch uses its MAC address as a unique system ID. 
#        This parameter is optional. 
#        In order for a port to be grouped in the same LAG with other ports, 
#        the actor system id must be the same for all ports.
#        This parameter is valid only when -mode is create/modify.
#        (DEFAULT = 0000.0000.0001)
#   -actor_system_id_step
#        The incrementing step for the system ID. 
#        Minimum value is 0. 
#        Maximum value is 65535. 
#        This parameter is optional. 
#        This parameter is valid only when -mode is create and -count is 
#        greater than 1.
#        (DEFAULT = 1)
#   -actor_system_pri
#        This field specifies the system priority of the link Actor. 
#        Minimum value is 0. 
#        Maximum value is 65535. 
#        This parameter is optional. 
#        In order for a port to be grouped in the same LAG with other ports, 
#        the actor system priority must be the same for all ports. 
#        This parameter is valid only when -mode is create/modify.
#        (DEFAULT = 1)
#   -actor_system_pri_step
#        The incrementing step for the system priority of the link Actor. 
#        Minimum value is 0. 
#        Maximum value is 65535. 
#        This parameter is optional.
#        (DEFAULT = 1)
#        This parameter is valid only when -mode is create and -count is 
#        greater than 1.
#   -aggregation_flag
#        If auto, this flag indicates that the System considers this link to 
#        be Aggregatable; i.e., a potential candidate for aggregation. If 
#        disabled, the link is considered to be Individual; i.e., this link 
#        can be operated only as an individual link. One of: auto, disable. 
#        This parameter is optional. 
#        This parameter is valid only when -mode is create/modify.
#        (DEFAULT = auto)
#   -auto_pick_port_mac
#        If enabled, the source MAC is the interface MAC address. One of: 0 1. 
#        This parameter is optional. 
#        This parameter is valid only when -mode is create/modify.
#        (DEFAULT = 1)
#   -collecting_flag
#        Set to 1, means collection of incoming frames on this link is 
#        definitely enabled; i.e., collection is currently enabled and is not 
#        expected to be disabled in the absence of administrative changes or 
#        changes in received protocol information. Its value is otherwise 0; 
#        i.e, the flag in LACPDU remains reset for all packets sent. 
#        One of: 0 1. This parameter is optional. 
#        This parameter is valid only when -mode is create/modify.
#        (DEFAULT = 1)
#   -collector_max_delay
#        The maximum time in microseconds that the Frame Collector may delay 
#        the delivery of a frame received from an Aggregator to its MAC 
#        client. This is a 2 byte field with a default 0.
#        Minimum value is 0. 
#        Maximum value is 65535. 
#        This parameter is optional. 
#        This parameter is valid only when -mode is create/modify.
#        (DEFAULT = 0)
#   -distributing_flag
#        Set to 0, means distribution of outgoing frames on this link is 
#        definitely disabled; i.e., distribution is currently disabled and is 
#        not expected to be enabled in the absence of administrative changes 
#        or changes in received protocol information. Its value is otherwise 1. 
#        This parameter is optional. 
#        This parameter is valid only when -mode is create/modify.
#        (DEFAULT = 1)
#   -handle
#        The link handle returned by a previous call to ::ixia::emulation_lacp_link_config. 
#        This parameter is mandatory when -mode is modify/enable/disable/delete.
#   -inter_marker_pdu_delay
#        Sets the marker the inter marker PDU interval. 
#        For marker_req_mode fixed the interval is the actual value provided.
#        For marker_req_mode fixed the interval is a value between 1 and the 
#        value provided through inter_marker_pdu_delay.
#        This field is inactive if send_periodic_marker_req is disabled.
#        This parameter is optional. 
#        This parameter is valid only when -mode is create/modify 
#        and -send_periodic_marker_req is 1.
#        (DEFAULT = 6)
#   -lacp_activity
#        Sets the value of LACPs Actor activity. 
#        This parameter is optional. This parameter is valid only when -mode is create/modify.
#        (DEFAULT = active) Valid choices are:
#        passive - Passive LACP indicates the port's preference for not 
#                  transmitting LACPDUs unless its Partner's control is Active.
#        active - Active LACP indicates the port's preference to participate 
#                 in the protocol regardless of the Partner's control value.
#   -lacp_timeout
#        This field defines the value of IEEE 802.3-2005 mentioned 
#        "current_while_timer" value. Long and short have values as mentioned 
#        in protocol specification. Auto can be used to derive the timeout 
#        value from received LACPDU and till any LACPDU is received, we follow 
#        the Rx state machine in section 43.4.12 Figure 43-10. 
#        This timer is used to detect whether received protocol information has expired. 
#        This parameter is optional. This parameter is valid only when -mode is create/modify.
#        (DEFAULT = auto) Valid choices are:
#        short - 3 seconds
#        long - 90 seconds
#        auto - the timeout value from received LACPDU and till any LACPDU is received, 
#               as defined in section 43.4.12 of IEEE 802.3-2005. 
#        The user can also provide a custom values from 1 to 65535.
#   -lacpdu_periodic_time_interval
#        This field defines how frequently LACPDUs are sent to the link partner. 
#        This parameter is optional. This parameter is valid only when -mode is create/modify.
#        (DEFAULT = auto) Valid choices are:
#        fast - 1 second
#        slow - 30 seconds
#        auto - follows the Periodic Tx state machine as defined in 
#               IEEE 802.3-2005 Section 43.4.13. 
#        The user can also provide a custom values from 1 to 65535.
#   -lag_count
#        The number of LACP LAGs to be created based on the number of ports 
#        provided and actor system id, actor system priority and actor key 
#        provided.
#        This parameter is optional. This parameter is valid only when -mode is create.
#        (DEFAULT = 1)
#        Example:
#            port_handle:           1/1/1 ... 1/1/12
#            lag_count:             3
#            actor_system_id        0000.0000.0001
#            actor_system_id_step   0000.0000.0002
#            actor_system_pri       1
#            actor_system_pri_step  2 
#            actor_key              1
#            actor_key_step         2
#            Results:
#            LAG1:
#            Ports                  1/1/1 1/1/4 1/1/7 1/1/10
#            System ID              0000.0000.0001
#            System Priority        1
#            Key                    1
#            
#            LAG2:
#            Ports                  1/1/2 1/1/5 1/1/8 1/1/11
#            System ID              0000.0000.0003
#            System Priority        3
#            Key                    3
#            
#            LAG3:
#            Ports                  1/1/3 1/1/6 1/1/9 1/1/12
#            System ID              0000.0000.0005
#            System Priority        5
#            Key                    5
#   -marker_req_mode
#        Sets the marker request mode for the Actor link. 
#        This field is inactive if send_periodic_marker_req is disabled.
#        This parameter is optional. 
#        This parameter is valid only when -mode is create/modify 
#        and -send_periodic_marker_req is 1.
#        (DEFAULT = fixed)
#        In either case, the mode parameters are specified in inter_marker_pdu_delay 
#        parameter. Valid choices are:
#        fixed - the inter marker PDU interval has to be provided as a single 
#                number.
#        random - the interval can be specified as a range.
#   -marker_res_wait_time
#        The number of seconds to wait for Marker Response after sending a 
#        Marker Request. After this time, the Marker Response Timeout Count is 
#        incremented. If a marker response does arrive for the request after 
#        this timeout, it is not considered as a legitimate response. 
#        This parameter is optional. 
#        This parameter is valid only when -mode is create/modify.
#        (DEFAULT = 5)
#   -mode
#        The action to be performed by ::ixia::emulation_lacp_link_config. 
#        This parameter is optional. Parameter -port_handle is mandatory when -mode is create, 
#        parameter -handle is mandatory when -mode is 
#        modify/enable/disable/delete.
#        (DEFAULT = create) Valid choices are:
#        create - create and configure a LACP link
#        modify - modify an existing LACP link configuration
#        enable - enable an existing LACP link configuration, all other links 
#                 will be disabled automatically
#        disable - disable an existing LACP link configuration
#        delete - delete LACP link
#   -no_write
#        If this flag is present, the LACP configuration will not be sent to 
#        the chassis and the configuration will be kept locally. On the first 
#        call without -no_write option all accumulated configurations will be 
#        written on the hardware.
#        This parameter is valid only with IxTclProtocol.
#   -port_handle
#        The Ixia ports where the action should be performed by 
#        ::ixia::emulation_lacp_link_config. 
#        This parameter is mandatory when -mode is create.
#   -port_mac
#        This field specifies the port MAC address. 
#        This parameter is optional. 
#        This parameter is valid only when -mode is create/modify 
#        and -auto_pick_port_mac is 0.
#        (DEFAULT = 0000.0000.0001)
#   -port_mac_step
#        The incrementing step for the port MAC address. 
#        This parameter is optional. 
#        This parameter is valid only when -mode is create 
#        and -auto_pick_port_mac is 0 and -count is greater than 1.
#        (DEFAULT = 0000.0000.0001)
#   -reset
#        If present, all previous LACP configuration will be reset from the port.
#        Valid only for -mode create.
#   -send_marker_req_on_lag_change
#        If enabled, this parameter causes LACP to send a Marker PDU on the 
#        following situations:
#        System Priority has been modified, 
#        System Id has been modified, 
#        Actor Key has been modified, 
#        Port Number/Port Priority has been modified while we are in 
#        Individual mode. 
#        This parameter is optional. 
#        This parameter is valid only when -mode is create/modify.
#        (DEFAULT = 1)
#   -send_periodic_marker_req
#        When this field is enabled, we shall periodically send Marker Request 
#        PDUs after both actor and partner are IN SYNC and our state is 
#        aggregated. The moment we come out of this state, the periodic 
#        sending of Marker will be stopped. 
#        This parameter is optional. 
#        This parameter is valid only when -mode is create/modify.
#        (DEFAULT = 0)
#   -support_responding_to_marker
#        This can be enabled for negative testing. When this is enabled, we 
#        shall not respond to MARKER request PDUs from the partner. 
#        This parameter is optional. 
#        This parameter is valid only when -mode is create/modify.
#        (DEFAULT = 1)
#   -sync_flag
#        If auto, the System considers this link to be IN_SYNC; i.e., it has 
#        been allocated to the correct Link Aggregation Group, the group has 
#        been associated with a compatible Aggregator, and the identity of the 
#        Link Aggregation Group is consistent with the System ID and 
#        operational Key information transmitted. If disabled, then this link 
#        is currently OUT_OF_SYNC; i.e., it is not in the right Aggregation. 
#        This parameter is optional. 
#        This parameter is valid only when -mode is create/modify.
#        (DEFAULT = 0)
#
# Return Values:
#    A keyed list
#    key:status         value:$::SUCCESS | $::FAILURE
#    key:log            value:On status of failure, gives detailed information.
#    key:handle         value:On mode create, list of LACP link handles
#
# Examples:
#    See files starting with LACP_ in the Samples subdirectory.
#
# Sample Input:
#
# Sample Output:
#
# Notes:
#    1) This protocol is available only when using IxTclProtocol API.
#
# See Also:
#
proc ::ixia::emulation_lacp_link_config { args } {
    variable executeOnTclServer
    variable new_ixnetwork_api
    
    set procName [lindex [info level [info level]] 0]
	
    ::ixia::logHltapiCommand $procName $args
    
    if {$::ixia::executeOnTclServer} {
        set retValue [eval clientSend $::ixTclSvrHandle \
                \{::ixia::emulation_lacp_config $args\}]
        
        set startIndex [string last "\r" $retValue]
        if {$startIndex >= 0} {
            set retData [string range $retValue [expr $startIndex + 1] end]
            return $retData
        } else {
            return $retValue
        }
    }

    ::ixia::utrackerLog $procName $args
    
    set opt_args {
        -actor_key                        RANGE 0-65535 
                                          DEFAULT 1
        -actor_key_step                   RANGE 0-65535 
                                          DEFAULT 1
        -actor_port_num                   RANGE 0-65535 
                                          DEFAULT 1
        -actor_port_num_step              RANGE 0-65535 
                                          DEFAULT 1
        -actor_port_pri                   RANGE 0-65535 
                                          DEFAULT 1
        -actor_port_pri_step              RANGE 0-65535 
                                          DEFAULT 1
        -actor_system_id                  MAC
        -actor_system_id_step             MAC
        -actor_system_pri                 RANGE 0-65535 
                                          DEFAULT 1
        -actor_system_pri_step            RANGE 0-65535 
                                          DEFAULT 1
        -aggregation_flag                 CHOICES auto disable 
                                          DEFAULT auto
        -auto_pick_port_mac               CHOICES 0 1 
                                          DEFAULT 1
        -collecting_flag                  CHOICES 0 1 
                                          DEFAULT 1
        -collector_max_delay              RANGE 0-65535 
                                          DEFAULT 0
        -distributing_flag                CHOICES 0 1 
                                          DEFAULT 1
        -handle
        -inter_marker_pdu_delay           RANGE 1-255
                                          DEFAULT 6
        -lacp_activity                    CHOICES active passive 
                                          DEFAULT active
        -lacp_timeout                     CHOICES short long auto RANGE 1-65535 
                                          DEFAULT auto
        -lacpdu_periodic_time_interval    CHOICES fast slow auto RANGE 1-65535 
                                          DEFAULT auto
        -lag_count                        NUMERIC
        -marker_req_mode                  CHOICES fixed random 
                                          DEFAULT fixed
        -marker_res_wait_time             RANGE 1-255
                                          DEFAULT 5
        -mode                             CHOICES create modify enable disable delete 
                                          DEFAULT create
        -no_write
        -port_handle                      REGEXP ^[0-9]+/[0-9]+/[0-9]+$
        -port_mac                         MAC
        -port_mac_step                    MAC
        -reset
        -send_marker_req_on_lag_change    CHOICES 0 1 
                                          DEFAULT 1
        -send_periodic_marker_req         CHOICES 0 1 
                                          DEFAULT 0
        -support_responding_to_marker     CHOICES 0 1 
                                          DEFAULT 1
        -sync_flag                        CHOICES auto disable 
                                          DEFAULT auto
    }
    if {[info exists new_ixnetwork_api] && $new_ixnetwork_api} {
        set returnList [::ixia::ixnetwork_lacp_link_config $args $opt_args]
        #keylset returnList status $::FAILURE
        #keylset returnList log "LACP is not supported with IxTclNetwork API."
    } else {
        set returnList [::ixia::ixprotocol_lacp_link_config $args $opt_args]
    }
    
    if {[keylget returnList status] == $::FAILURE} {
        keylset returnList status $::FAILURE
        keylset returnList log "ERROR in $procName: \
                [keylget returnList log]"
    }
    return $returnList
}

##Procedure Header
# Name:
#    ::ixia::emulation_lacp_control
#
# Description:
#    This procedure performs actions for LACP configurations: start/stop/restart  
#    protocol, start/stop sending PDU, send Marker Request, update link 
#    parameters after the link has been modified. 
#
# Synopsis:
#    ::ixia::emulation_lacp_control
#        [-handle]
#        -mode              CHOICES start stop restart start_pdu stop_pdu send_marker_req update_link
#        [-port_handle       REGEXP  ^[0-9]+/[0-9]+/[0-9]+$]
#
# Arguments:
#   -handle
#        The link handle which indicates the port where action will be performed. 
#        One of -handle or port_handle must be present.
#   -mode
#        The action that will be performed. Valid choices are:
#        restart - stop and then start LACP protocol
#        send_marker_req - This action is used to send Marker Requests at 
#                          will. The contents of the marker PDU contain the 
#                          current view of partner (which can be defaulted if 
#                          no partner is present). The marker will be sent 
#                          regardless of which state the link is in.
#        start - start LACP protocol
#        start_pdu - This action is used start PDUs related to LACP (for 
#                    example, LACPDU, Marker Request PDU, Marker Response PDU) 
#                    while the protocol is running on the port. By default, 
#                    when LACP is started, PDUs are sent as per the protocol 
#                    and this action is disabled. It is enabled after the Stop 
#                    PDU action is performed. This action is disabled if no 
#                    links are enabled or the protocol is not running.
#        stop - stop LACP protocol
#        stop_pdu - This action is used stop PDUs related to LACP (for 
#                   example, LACPDU, Marker Request PDU, Marker Response PDU) 
#                   while the protocol is running on the port. By default, 
#                   when LACP is started PDUs are sent as per the protocol and 
#                   this action is enabled. This action is disabled if no 
#                   links are enabled or the protocol is not running.
#        update_link - Perform this action after changing a link's 
#                      configuration parameters. This button is not active 
#                      until a link's parameters have been altered.
#   -port_handle
#        The port where action will be performed.
#        One of -handle or port_handle must be present.
#
# Return Values:
#    A keyed list
#    key:status          value:$::SUCCESS | $::FAILURE
#    key:log             value:On status of failure, gives detailed information.
#
# Examples:
#    See files starting with LACP_ in the Samples subdirectory.
#
# Sample Input:
#
# Sample Output:
#
# Notes:
#
# See Also:
#
proc ::ixia::emulation_lacp_control { args } {
    variable executeOnTclServer
    variable new_ixnetwork_api
    
    set procName [lindex [info level [info level]] 0]
	
    ::ixia::logHltapiCommand $procName $args
    
    if {$::ixia::executeOnTclServer} {
        set retValue [eval clientSend $::ixTclSvrHandle \
                \{::ixia::emulation_lacp_control $args\}]
        
        set startIndex [string last "\r" $retValue]
        if {$startIndex >= 0} {
            set retData [string range $retValue [expr $startIndex + 1] end]
            return $retData
        } else {
            return $retValue
        }
    }

    ::ixia::utrackerLog $procName $args
    
    set man_args {
        -mode          CHOICES restart send_marker_req start start_pdu stop stop_pdu update_link
    }
    set opt_args {
        -port_handle   REGEXP  ^[0-9]+/[0-9]+/[0-9]+$
        -handle
    }

    if {[info exists new_ixnetwork_api] && $new_ixnetwork_api} {
        set returnList [::ixia::ixnetwork_lacp_control $args $man_args $opt_args]
        #keylset returnList status $::FAILURE
        #keylset returnList log "LACP is not supported with IxTclNetwork API."
        
    } else {
        set returnList [::ixia::ixprotocol_lacp_control $args $man_args $opt_args]
    }
    
    if {[keylget returnList status] == $::FAILURE} {
        keylset returnList status $::FAILURE
        keylset returnList log "ERROR in $procName: \
                [keylget returnList log]"
    }
    return $returnList
}

##Procedure Header
# Name:
#    ::ixia::emulation_lacp_info
#
# Description:
#    This procedure retrieves information about the LACP sessions. 
#
# Synopsis:
#    ::ixia::emulation_lacp_info
#        [-handle]
#        -mode              CHOICES aggregate_stats learned_info clear_stats
#        [-port_handle       REGEXP  ^[0-9]+/[0-9]+/[0-9]+$]
#
# Arguments:
#   -handle
#       The handles that indicate the ports from which to extract LACP data. 
#       One of -handle or port_handle must be present.
#   -mode
#       The action that should be taken. Valid choices are:
#       aggregate_stats - retrieve stats aggregated per port
#       learned_info - retrieve learned information by the LACP protocol
#       clear_stats - clear stats
#   -port_handle
#       The ports from which to extract LACP data. 
#       One of -handle or port_handle must be present.
#
# Return Values:
#    A keyed list
#    key:status          value:$::SUCCESS | $::FAILURE
#    key:log             value:On status of failure, gives detailed information.
#
#    key:   value: 
#    key:Learned info:    value: 
#    key:<port_handle>.actor_system_id            value: MAC
#    key:<port_handle>.actor_system_pri           value: integer
#    key:<port_handle>.actor_port_num             value: integer
#    key:<port_handle>.actor_op_key               value: integer
#    key:<port_handle>.actor_port_pri             value: integer
#    key:<port_handle>.actor_lacp_activity        value: 1 - Active | 0 - Passive
#    key:<port_handle>.actor_lacp_timeout         value: Long | Short
#    key:<port_handle>.actor_aggregation          value: 1 - Aggregateable | 0 - Individual
#    key:<port_handle>.actor_sync_flag            value: 1 - IN SYNC | 0 - OUT OF SYNC
#    key:<port_handle>.actor_collecting_flag      value: 0 | 1
#    key:<port_handle>.actor_distributing_flag    value: 0 | 1
#    key:<port_handle>.actor_defaulted_flag       value: 0 | 1
#    key:<port_handle>.actor_expired_flag         value: 0 | 1
#    key:<port_handle>.actor_link_aggregation_status    value: 1 - Aggregated | 0 - Not Aggregated
#    key:<port_handle>.partner_system_id          value: MAC
#    key:<port_handle>.partner_system_pri         value: integer
#    key:<port_handle>.partner_port_num           value: integer
#    key:<port_handle>.partner_op_key             value: integer
#    key:<port_handle>.partner_port_pri           value: integer
#    key:<port_handle>.partner_lacp_activity      value: 1 - Active | 0 - Passive
#    key:<port_handle>.partner_lacp_timeout       value: Long | Short
#    key:<port_handle>.partner_aggregation        value: 1 - Aggregateable | 0 - Individual
#    key:<port_handle>.partner_sync_flag          value: 1 - IN SYNC | 0 - OUT OF SYNC
#    key:<port_handle>.partner_collecting_flag    value: 0 | 1
#    key:<port_handle>.partner_distributing_flag  value: 0 | 1
#    key:<port_handle>.partner_defaulted_flag     value: 0 | 1
#    key:<port_handle>.partner_expired_flag       value: 0 | 1
#    key:<port_handle>.partner_collectors_max_delay       value: integer
#    key:   value: 
#    key:Aggregate stats:   value: 
#    key:<port_handle>.aggregate.link_state                         value: 0 | 1
#    key:<port_handle>.aggregate.lacpdu_rx                          value: integer
#    key:<port_handle>.aggregate.lacpdu_tx                          value: integer
#    key:<port_handle>.aggregate.lacpu_malformed_rx                 value: integer
#    key:<port_handle>.aggregate.marker_pdu_rx                      value: integer
#    key:<port_handle>.aggregate.marker_pdu_tx                      value: integer
#    key:<port_handle>.aggregate.marker_res_pdu_rx                  value: integer
#    key:<port_handle>.aggregate.marker_res_pdu_tx                  value: integer
#    key:<port_handle>.aggregate.marker_res_timeout_count           value: integer
#    key:<port_handle>.aggregate.lacpdu_tx_rate_violation_count     value: integer
#    key:<port_handle>.aggregate.marker_pdu_tx_rate_violation_count value: integer
#    key:   value: 
#    key:Configuration stats:   value: 
#    key:lag.<lag_id>.ports                                         value: port handles
#    key:lag.<lag_id>.actor_system_id                               value: MAC
#    key:lag.<lag_id>.actor_system_pri                              value: integer
#    key:lag.<lag_id>.actor_key                                     value: integer
#    key:lag.<lag_id>.<port_handle>.active_link                     value: link handle
#    key:lag.<lag_id>.<port_handle>.links                           value: link handles
# Examples:
#    See files starting with LACP_ in the Samples subdirectory.
#
# Sample Input:
#
# Sample Output:
#
# Notes:
#
# See Also:
#
proc ::ixia::emulation_lacp_info { args } {
    variable executeOnTclServer
    variable new_ixnetwork_api
    
    set procName [lindex [info level [info level]] 0]
	
    ::ixia::logHltapiCommand $procName $args
    
    if {$::ixia::executeOnTclServer} {
        set retValue [eval clientSend $::ixTclSvrHandle \
                \{::ixia::emulation_lacp_info $args\}]
        
        set startIndex [string last "\r" $retValue]
        if {$startIndex >= 0} {
            set retData [string range $retValue [expr $startIndex + 1] end]
            return $retData
        } else {
            return $retValue
        }
    }

    ::ixia::utrackerLog $procName $args
    
    set man_args {
        -mode          CHOICES aggregate_stats learned_info clear_stats configuration
    }
    set opt_args {
        -handle
        -port_handle   REGEXP  ^[0-9]+/[0-9]+/[0-9]+$
    }

    if {[info exists new_ixnetwork_api] && $new_ixnetwork_api} {
        set returnList [::ixia::ixnetwork_lacp_info $args $man_args $opt_args]
        #keylset returnList status $::FAILURE
        #keylset returnList log "LACP is not supported with IxTclNetwork API."
        
    } else {
        set returnList [::ixia::ixprotocol_lacp_info $args $man_args $opt_args]
    }
    
    if {[keylget returnList status] == $::FAILURE} {
        keylset returnList status $::FAILURE
        keylset returnList log "ERROR in $procName: \
                [keylget returnList log]"
    }
    return $returnList
}
