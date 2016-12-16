##Library Header
# $Id: $
# Copyright © 2003-2007 by IXIA
# All Rights Reserved.
#
# Name:
#    ixnetwork_lacp_api.tcl
#
# Purpose:
#     A script development library containing LACP APIs for test automation
#     with the Ixia chassis.
#
# Description:
#    The procedures contained within this library include:
#
#    - ixnetwork_lacp_link_config
#    - ixnetwork_lacp_control
#    - ixnetwork_lacp_info
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
# This file is derived from the original ixnetwork_lacp_api.tcl
# Modified in order to support LACP configuration using IxTclNetwork API

# Copyright © 2014 Intel Corp
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Intel Corp license agreement.

proc ::ixia::ixnetwork_lacp_link_config { args opt_args } {
    variable objectMaxCount
    if {[catch {::ixia::parse_dashed_args -args $args \
            -optional_args $opt_args} parse_error]} {
        keylset returnList status $::FAILURE
        keylset returnList log "Failed on parsing. $parse_error"
        return $returnList
    }
    
    # Check to see if a connection to the IxNetwork TCL Server already exists. 
    # If it doesn't, establish it.
    set retCode [checkIxNetwork]
    if {[keylget retCode status] != $::SUCCESS} {
        keylset returnList status $::FAILURE
        keylset returnList log "Unable to connect to IxNetwork - \
                [keylget retCode log]"
        return $returnList
    }
    
    # Check is -mode parameter dependencies are provided
    if {($mode == "create")} {
        if {![info exists port_handle]} {
            keylset returnList status $::FAILURE
            keylset returnList log "When -mode is $mode,\
                    parameter -port_handle must be provided."
            return $returnList
        }
    } else {
        if {![info exists handle]} {
            keylset returnList status $::FAILURE
            keylset returnList log "When -mode is $mode,\
                    parameter -handle must be provided."
            return $returnList
        }
        if {$handle == ""} {
            keylset returnList status $::FAILURE
            keylset returnList log "Invalid parameter -handle {$handle}."
            return $returnList
        }
    }
    
    # Remove default values for -mode modify
    if {$mode == "modify"} {
        removeDefaultOptionVars $opt_args $args
    }
       
    array set lacpLinkOptionsArray {
        enabled                          link_enabled
        actorKey                         actor_key
        actorPortNumber                  actor_port_num
        actorPortPriority                actor_port_pri
        actorSystemId                    actor_system_id
        actorSystemPriority              actor_system_pri
        aggregationFlagState             aggregation_flag
        autoPickPortMac                  auto_pick_port_mac
        collectingFlag                   collecting_flag
        collectorMaxDelay                collector_max_delay
        distributingFlag                 distributing_flag
        lacpActivity                     lacp_activity
        lacpTimeout                      lacp_timeout
        lacpduPeriodicTimeInterval       lacpdu_periodic_time_interval
        markerRequestMode                marker_req_mode
        markerResponseWaitTime           marker_res_wait_time
        portMac                          port_mac
        sendMarkerRequestOnLagChange     send_marker_req_on_lag_change
        sendPeriodicMarkerRequest        send_periodic_marker_req
        supportRespondingToMarker        support_responding_to_marker
        syncFlag                         sync_flag
    }
    
    array set enabledValue {
        create     true
        enable     true
        disable    false
    }
    if {[info exists enabledValue($mode)]} {
        set link_enabled    $enabledValue($mode)
    }   
    
    if {$mode == "delete"} {
        foreach {linkHandle} $handle {
            if {[ixNet remove $linkHandle] != "::ixNet::OK"} {
                keylset returnList status $::FAILURE
                keylset returnList log "Failed to remove handle $linkHandle."
                return $returnList
            }
        }
        if {[ixNet commit] != "::ixNet::OK"} {
            keylset returnList status $::FAILURE
            keylset returnList log "Failed to remove -handle $handle."
            return $returnList
        }
        
        keylset returnList status $::SUCCESS
        return $returnList
    }

    if {($mode == "enable") || ($mode == "disable")} {
        foreach {linkHandle} $handle {
            set retCode [ixNetworkNodeSetAttr $linkHandle [list -enabled $link_enabled]]
            if {[keylget retCode status] != $::SUCCESS} {
                return $retCode
            }
        }
        if {[ixNet commit] != "::ixNet::OK"} {
            keylset returnList status $::FAILURE
            keylset returnList log "Failed to $mode -handle $handle."
            return $returnList
        }
        
        keylset returnList status $::SUCCESS
        return $returnList
    }
    
    if {$mode == "create"} {
        set lacp_link_list ""
        set objectCount     0
        set lagId           0
        set step_params {
            actor_key           integer,0-65535
            actor_port_num      integer,0-65535
            actor_port_pri      integer,0-65535
            actor_system_id     mac
            actor_system_pri    integer,0-65535
            port_mac            mac
        }
        foreach {step_param param_type} $step_params {
            if {[info exists $step_param]} {
                if {$param_type == "mac"} {
                    set ${step_param}      [convertToIxiaMac [set ${step_param}]]
                    if {[info exists ${step_param}_step]} {
                        set ${step_param}_step [convertToIxiaMac [set ${step_param}_step]]
                    }
                }
                set ${step_param}_start [set $step_param]
            }
        }
        foreach port_handle_i $port_handle {
            # Add port after connecting to IxNetwork TCL Server
            set retCode [ixNetworkPortAdd $port_handle_i {} force]
            if {[keylget retCode status] == $::FAILURE} {
                return $retCode
            }
            set retCode [ixNetworkGetPortObjref $port_handle_i]
            if {[keylget retCode status] == $::FAILURE} {
                keylset returnList status $::FAILURE
                keylset returnList log "Unable to find the port object reference \
                        associated to the $port_handle_i port handle -\
                        [keylget retCode log]."
                return $returnList
            }
            set vport_objref_i    [keylget retCode vport_objref]
            set protocol_objref_i [keylget retCode vport_objref]/protocols/lacp
            # Check if protocols are supported
            set retCode [checkProtocols $vport_objref_i]
            if {[keylget retCode status] != $::SUCCESS} {
                keylset returnList status $::FAILURE
                keylset returnList log "Port $port_handle_i does not support protocol\
                        configuration."
                return $returnList
            }
            
            if {[info exists reset]} {
                set result [ixNetworkNodeRemoveList $protocol_objref_i \
                        { {child remove link} {} } -commit]
                if {[keylget result status] == $::FAILURE} {
                    return $returnList
                }
            }

            ixNet setAttr $protocol_objref_i -enabled true
            
            # Compose list of LACP link options
            set lacp_link_args ""
            foreach {ixnOpt hltOpt}  [array get lacpLinkOptionsArray] {
                if {[info exists $hltOpt]} {
                    lappend lacp_link_args -$ixnOpt [set $hltOpt]
                }
            }
                
            # Create link
            set retCode [ixNetworkNodeAdd $protocol_objref_i link \
                    $lacp_link_args]
            if {[keylget retCode status] == $::FAILURE} {
                keylset returnList status $::FAILURE
                keylset returnList log "Failed to add LACP router.\
                        [keylget retCode log]."
                return $returnList
            }
            set link_objref [keylget retCode node_objref]
            if {$link_objref == [ixNet getNull]} {
                keylset returnList status $::FAILURE
                keylset returnList log "Failed to add link to the \
                        $protocol_objref_i protocol object reference."
                return $returnList
            }
            incr objectCount
            if {$objectCount == $objectMaxCount} {
                debug "ixNet commit"
                ixNet commit
                set objectCount 0
            }
            lappend lacp_link_list $link_objref
            
            incr lagId
            # Increment params with steps
            foreach {step_param param_type} $step_params {
                if {[info exists ${step_param}] && [info exists ${step_param}_step]} {
                    switch --[lindex [split $param_type ,] 0] {
                        integer {
                            set param_range [lindex [split $param_type ,] 1]
                            set param_start [lindex [split $param_range -] 0]
                            set param_end   [lindex [split $param_range -] 1]
                            incr ${step_param} [set ${step_param}_step]
                            if {[set ${step_param}] > $param_end} {
                                set ${step_param} $param_start
                            }
                        }
                        mac {
                            set ${step_param}_temp      [join [convertToIxiaMac [set ${step_param}]] :]
                            set ${step_param}_step_temp [join [convertToIxiaMac [set ${step_param}_step]] :]
                            set ${step_param} [split [incr_mac_addr \
                                    [join [set ${step_param}] :]
                                    [join [set ${step_param}_step] :]
                                    ] :]
                        }
                    }
                }
            }
            if {$lagId == $lag_count} {
                set lagId 0
                # Reset params with steps
                foreach {step_param param_type} $step_params {
                    if {[info exists ${step_param}_start]} {
                        set ${step_param} [set ${step_param}_start]
                    }
                }
            }
        }
        if {$lacp_link_list != ""} {
            set lacp_link_list [ixNet remapIds $lacp_link_list]
        }
        
        keylset returnList status $::SUCCESS
        keylset returnList handle $lacp_link_list
        return $returnList
    }
    
    if {$mode == "modify"} {
        # Compose list of link options
        set lacp_router_args ""
        foreach {ixnOpt hltOpt}  [array get lacpLinkOptionsArray] {
            if {[info exists $hltOpt]} {
                set length [llength [set $hltOpt]]
                if {$length == [llength $handle]} {
                    lappend lacp_link_args -$ixnOpt \
                            "\[lindex [set $hltOpt] \$handleIndex\]"
                } elseif {$length == 1} {
                    lappend lacp_link_args -$ixnOpt [set $hltOpt]
                } else {
                    keylset returnList status $::FAILURE
                    keylset returnList log "Invalid number of values\
                            for -$hltOpt. The number of values\
                            should be 1 or [llength $handle]."
                    return $returnList
                }
            }
        }
        set handleIndex 0
        foreach {linkHandle} $handle {
            if {![regexp {link:\d*$} $linkHandle]} {
                keylset returnList status $::FAILURE
                keylset returnList log "Invalid LACP handle $linkHandle. Parameter\
                        -handle must provide with a list of LACP links."
                return $returnList
            }
            set link_objref  $linkHandle
            set retCode [ixNetworkGetPortFromObj $linkHandle]
            if {[keylget retCode status] == $::FAILURE} {
                return $retCode
            }
            set port_handle  [keylget retCode port_handle]
            set vport_objref [keylget retCode vport_objref]
            set protocol_objref [keylget retCode vport_objref]/protocols/lacp
            
             
            # Setting link arguments
            if {$lacp_router_args != ""} {
                set retCode [ixNetworkNodeSetAttr $link_objref \
                        [subst $lacp_link_args]]
                if {[keylget retCode status] == $::FAILURE} {
                    return $retCode
                }
            }
            incr handleIndex
        }
        
        ixNet commit
        
        keylset returnList status $::SUCCESS
        return $returnList
    }
}


proc ::ixia::ixnetwork_lacp_control {args man_args opt_args} {
    if {[catch {::ixia::parse_dashed_args -args $args \
            -mandatory_args $man_args -optional_args $opt_args} parse_error]} {
        keylset returnList status $::FAILURE
        keylset returnList log "Failed on parsing. $parse_error"
        return $returnList
    }
    
    if {![info exists port_handle] && ![info exists handle]} {
        keylset returnList status $::FAILURE
        keylset returnList log "When -mode is $mode, parameter -port_handle or\
                parameter -handle must be provided."
        return $returnList
    }
    set protocol lacp
    if {[info exists port_handle]} {
        set _handles $port_handle
        set protocol_objref_list ""
        foreach {_handle} $_handles {
            set retCode [ixNetworkGetPortObjref $_handle]
            if {[keylget retCode status] == $::FAILURE} {
                return $retCode
            }
            set protocol_objref [keylget retCode vport_objref]
            lappend protocol_objref_list $protocol_objref/protocols/$protocol
        }
        if {$protocol_objref_list == "" } {
            keylset returnList status $::FAILURE
            keylset returnList log "All handles provided through -port_handle\
                    parameter are invalid."
            return $returnList
        }
    }
    if {[info exists handle]} {
        set _handles $handle
        set protocol_objref_list ""
        foreach {_handle} $_handles {
           if {[regexp "^\[0-9\]+/\[0-9\]+/\[0-9\]+$" $_handle]} {
                set retCode [ixNetworkGetPortObjref $_handle]
                if {[keylget retCode status] == $::FAILURE} {
                    return $retCode
                }
                set protocol_objref [keylget retCode vport_objref]
                lappend protocol_objref_list $protocol_objref/protocols/$protocol
            } else {
                set retCode [ixNetworkGetProtocolObjref $_handle $protocol]
                if {[keylget retCode status] == $::FAILURE} {
                    return $retCode
                }
                set protocol_objref [keylget retCode objref]
                if {$protocol_objref != [ixNet getRoot]} {
                    lappend protocol_objref_list $protocol_objref
                }
            }
        }
        if {$protocol_objref_list == "" } {
            keylset returnList status $::FAILURE
            keylset returnList log "All handles provided through -handle\
                    parameter are invalid."
            return $returnList
        }
    }
    
    # Check link state
    foreach protocol_objref $protocol_objref_list {
        regexp {(::ixNet::OBJ-/vport:\d).*} $protocol_objref {} vport_objref
        set retries 60
        set portState  [ixNet getAttribute $vport_objref -state]
        set portStateD [ixNet getAttribute $vport_objref -stateDetail]
        while {($retries > 0) && ( \
                ($portStateD != "idle") || ($portState  == "busy"))} {
            debug "Port state: $portState, $portStateD ..."
            after 1000
            set portState  [ixNet getAttribute $vport_objref -state]
            set portStateD [ixNet getAttribute $vport_objref -stateDetail]
            incr retries -1
        }
        debug "Port state: $portState, $portStateD ..."
        if {($portStateD != "idle") || ($portState == "busy")} {
            keylset returnList status $::FAILURE
            keylset returnList log "Failed to $mode [string toupper $protocol]\
                    on the $vport_objref port.\
                    Port state is $portState, $portStateD."
            return $returnList
        }
    }
    
    switch -- $mode {
        send_marker_req {
            set operations [list sendMarkerRequest]
        }
        start {
            set operations [list start]
        }
        stop {
            set operations [list stop]
        }
        restart {
            set operations [list stop start]
        }
        start_pdu {
            set operations [list startPDU]
        }
        stop_pdu {
            set operations [list stopPDU]
        }
        update_link {
            set operations [list sendUpdate]
        }
    }
    
    # timeout in seconds waiting for start/stop
    set timeout 300
    foreach operation $operations {
        foreach protocol_objref $protocol_objref_list {
            debug "ixNetworkExec [list $operation $protocol_objref]"
            if {[catch {ixNetworkExec [list $operation $protocol_objref]} retCode] || \
                    ([string first "::ixNet::OK" $retCode] == -1)} {
                keylset returnList status $::FAILURE
                keylset returnList log "Failed to ${operation}\
                        [string toupper $protocol] on the\
                        $vport_objref port. $retCode."
                return $returnList
            }
        }
        set not_yet_started 1
        set start_time [clock seconds]
        while {[expr [clock seconds] - $start_time] < $timeout &&\
                $not_yet_started} {
            set not_yet_started 0
            foreach protocol_objref $protocol_objref_list {
                set current_state [ixNet getAttribute $protocol_objref\
                        -runningState]
                if {$current_state == "starting" ||\
                        $current_state == "stopping"} {
                    set not_yet_started 1
                    after 1000
                    break
                }
            }
        }
        if {$current_state == "unknown"} {
            keylset returnList status $::FAILURE
            keylset returnList log "State 'unknown' found on $protocol_objref."
            return $returnList
        }
        if {$not_yet_started} {
            keylset returnList status $::FAILURE
            keylset returnList log "Timeout $timeout occur waiting protocol to\
                    start."
            return $returnList
        }
    }
    keylset returnList status $::SUCCESS
    return $returnList
}


proc ::ixia::ixnetwork_lacp_info { args man_args opt_args } {
    if {[catch {::ixia::parse_dashed_args -args $args -mandatory_args $man_args \
            -optional_args $opt_args} parse_error]} {
        keylset returnList status $::FAILURE
        keylset returnList log "Failed on parsing. $parse_error"
        return $returnList
    }
    
    if {[info exists port_handle]} {
        set port_objrefs   ""
        foreach {port} $port_handle {
            set retCode [ixNetworkGetPortObjref $port]
            if {[keylget retCode status] == $::FAILURE} {
                return $retCode
            }
            set vport_objref [keylget retCode vport_objref]
            lappend port_objrefs $vport_objref
        }
    }
    if {[info exists handle]} {
        set port_objrefs   ""
        foreach {_handle} $handle {
            if {![regexp {^(.*)/protocols/lacp/link:\d$} $_handle {} port_objref]} {
                keylset returnList status $::FAILURE
                keylset returnList log "The handle $handle is not a valid\
                        LACP link handle."
                return $returnList
            }
            set retCode [ixNetworkGetPortFromObj $_handle]
            if {[keylget retCode status] == $::FAILURE} {
                return $retCode
            }
            lappend port_objrefs  [keylget retCode vport_objref]
        }
    }
    set port_objrefs [lsort -unique $port_objrefs]
    keylset returnList status $::SUCCESS
    
    if {$mode == "clear_stats"} {
        if {[set retCode [catch {ixNet exec clearStats} retCode]]} {
            keylset returnList status $::FAILURE
            keylset returnList log "Unable to clear statistics."
            return $returnList
        }
    }
    
    if {$mode == "learned_info"} {
        set stats_list {
            actorCollectingFlag             actor_collecting_flag
            actorDefaultedFlag              actor_defaulted_flag
            actorDistributingFlag           actor_distributing_flag
            actorExpiredFlag                actor_expired_flag
            actorLacpActivity               actor_lacp_activity
            actorLacpTimeout                actor_lacp_timeout
            actorLinkAggregationStatus      actor_link_aggregation_status
            actorOperationalKey             actor_op_key
            actorPortNumber                 actor_port_num
            actorPortPriority               actor_port_pri
            actorSyncFlag                   actor_sync_flag
            actorSystemId                   actor_system_id
            actorSystemPriority             actor_system_pri
            enabledAggregation              actor_aggregation
            partnerCollectingFlag           partner_collecting_flag
            partnerCollectorMaxDelay        partner_collectors_max_delay
            partnerDefaultedFlag            partner_defaulted_flag
            partnerDistributingFlag         partner_distributing_flag
            partnerExpiredFlag              partner_expired_flag
            partnerLacpActivity             partner_lacp_activity
            partnerLacpTimeout              partner_lacp_timeout
            partnerLinkAggregationStatus    partner_aggregation
            partnerOperationalKey           partner_op_key
            partnerPortNumber               partner_port_num
            partnerPortPriority             partner_port_pri
            partnerSyncFlag                 partner_sync_flag
            partnerSystemId                 partner_system_id
            partnerSystemPriority           partner_system_pri
        }
        
        foreach {port} $port_objrefs {
            set retCode [ixNet exec refreshLacpPortLearnedInfo $port/protocols/lacp]
            if {[string first "::ixNet::OK" $retCode] == -1 } {
                keylset returnList status $::FAILURE
                keylset returnList log "Failed to refresh learned info for\
                        port $port."
                return $returnList
            }
            set retries 10
            while {[ixNet getAttribute $port/protocols/lacp -isLacpPortLearnedInfoRefreshed] != "true"} {
                after 10
                incr retries -1
                if {$retries < 0} {
                    keylset returnList status $::SUCCESS
                    keylset returnList log "Refreshing learned info for\
                            port $port has timed out. Please try again later."
                    
                    set session 1
                    foreach {ixnOpt hltOpt} $stats_list {
                        set lst [split [ixNet getAttribute $port -connectedTo] "/"]
                        set card_n [lindex [split [lindex $lst 3] ":"] 1]
                        set port_n [lindex [split [lindex $lst 4] ":"] 1]
                        keylset returnList 1/$card_n/$port_n.$hltOpt \
                                "NA"
                    }
                    
                    return $returnList
                }
            }
            set learnedInfoList [ixNet getList $port/protocols/lacp learnedInfo]
            set session 1
            foreach {learnedInfo} $learnedInfoList {
                foreach {ixnOpt hltOpt} $stats_list {
                    set lst [split [ixNet getAttribute $port -connectedTo] "/"]
                    set card_n [lindex [split [lindex $lst 3] ":"] 1]
                    set port_n [lindex [split [lindex $lst 4] ":"] 1]
                    keylset returnList 1/$card_n/$port_n.$hltOpt \
                            [ixNet getAttribute $learnedInfo -$ixnOpt]
                }
                incr session
            }
        }
        
        return $returnList
    }
    
    if {$mode == "aggregate_stats"} {        
        array set stats_array_aggregate {
            "Link State"
            link_state
            "LACPDU Rx"
            lacpdu_rx
            "LACPDU Tx"
            lacpdu_tx
            "LACPDU Malformed Rx"
            lacpu_malformed_rx
            "Marker PDU Rx"
            marker_pdu_rx
            "Marker PDU Tx"
            marker_pdu_tx
            "Marker Response PDU Rx"
            marker_res_pdu_rx
            "Marker Response PDU Tx"
            marker_res_pdu_tx
            "Marker Response Timeout Count"
            marker_res_timeout_count
            "LACPDU Tx Rate Violation Count"
            lacpdu_tx_rate_violation_count
            "Marker PDU Tx Rate Violation Count"
            marker_pdu_tx_rate_violation_count
        }
                
        set statistic_types {
            aggregate "LACP Aggregated Statistics"
        }
        
        foreach {stat_type stat_name} $statistic_types {
            set stats_array_name stats_array_${stat_type}
            array set stats_array [array get $stats_array_name]

            set returned_stats_list [ixNetworkGetStats \
                    $stat_name [array names stats_array]]
            if {[keylget returned_stats_list status] == $::FAILURE} {
                keylset returnList status $::FAILURE
                keylset returnList log "Unable to read\
                        $stat_name from stat view browser.\
                        [keylget returned_stats_list log]"
                return $returnList
            }

            set found false
            set row_count [keylget returned_stats_list row_count]
            array set rows_array [keylget returned_stats_list statistics]
            for {set i 1} {$i <= $row_count} {incr i} {
                set row_name $rows_array($i)
                set match [regexp {([0-9.]+)/Card([0-9]{2})/Port([0-9]{2})} \
                        $row_name match_name chassis_ip card_no port_no]
                if {$match && ($match_name == $row_name) && \
                        [info exists chassis_ip] && [info exists card_no] && \
                        [info exists port_no] } {
                    set chassis_no [ixNetworkGetChassisId $chassis_ip]
                } else {
                    keylset returnList status $::FAILURE
                    keylset returnList log "Unable to interpret the '$row_name'\
                            row name."
                    return $returnList
                }
                regsub {^0} $card_no "" card_no
                regsub {^0} $port_no "" port_no

                if {[lsearch $port_handle "$chassis_no/$card_no/$port_no"] != -1} {
                    set found true
                    set port "$chassis_no/$card_no/$port_no"
                    foreach stat [array names stats_array] {
                        if {[info exists rows_array($i,$stat)] && \
                                $rows_array($i,$stat) != ""} {
                            keylset returnList ${port}.${stat_type}.$stats_array($stat) \
                                    $rows_array($i,$stat)
                        } else {
                            keylset returnList ${port}.${stat_type}.$stats_array($stat) "N/A"
                        }
                    }
                }
            }
            if {!$found} {
                keylset returnList status $::FAILURE
                keylset returnList log "The '$port' port couldn't be\
                        found among the ports from which statistics were\
                        gathered."
                return $returnList
            }
        }
    }
    
    return $returnList
}
