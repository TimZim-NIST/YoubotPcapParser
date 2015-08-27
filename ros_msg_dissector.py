#
# Author:       Timothy Zimmerman (timothy.zimmerman@nist.gov)
# Organization: National Institute of Standards and Technology
#               U.S. Department of Commerce
# License:      Public Domain
#
# Description:  
#

from string import *
from struct import *

# List of lists that specifies specific message text to look for in the 
# packet data for identification. Format: [id, [idx, "text"], ... , [idx, "text"]]
# NOTE: Function that uses this tuple will accept as many idx&text pairs provided

ROS_PACKETS = [ [0, [28, "arm_joint_1"], [43, "arm_joint_2"]],      # JointState Message
                [0, [28, "arm_2_joint_1"], [45, "arm_2_joint_2"]],  # JointState Message
                
                [1, [32, "arm_joint_1"], [47, "rad"]],              # Brics Action Message
                [1, [32, "arm_2_joint_1"], [49, "rad"]],            # Brics Action Message
                
                [2, [25, "/robot_proxy_1"]],                        # Debug Message
                [2, [25, "/robot_proxy_2"]],                        # Debug Message
                
                [3, [20, "youbot_dependency_update"]],              # Dependency
                
                [4, [32, "gripper_finger_joint_"]],                 # Gripper Message
                [4, [32, "gripper_2_finger_joint_"]]                # Gripper Message
]  
ROS_PACKET_TYPES = "JointStateMsg", "BricsPositionMsg", "rosgraphDebugMsg", "DependencyMsg", "GripperMsg"

def dissectJointStateMsg(unpack_header, packet_data):

    # Clear the output dictionary, and add the msg type
    returnInfo = {'ros_msg_type': ROS_PACKET_TYPES[0]}    
    
    # Unpack the header
    ros_header = unpack(unpack_header + 'IIIII', packet_data[0:20])

    # If our packet size is larger than 3500, we can guess it's a false positive
    if ros_header[0] > 3500:
        return {}

    returnInfo['ros_msg_len'] = str(ros_header[0])
    returnInfo['ros_frame_id'] = str(ros_header[1])
    returnInfo['ros_time'] = str(ros_header[2]) + "." + str(ros_header[3])
    
    # Is there a sequence number?
    if ros_header[4] > 0:
        # If so, let's store the value
        returnInfo['ros_seq_num'] = str(packet_data[20:20+ros_header[4]])
    # Remove the ROS header
    packet_data = packet_data[20 + ros_header[4]:]

    #######################
    # Get the joint names #
    #######################

    # What size is this array?
    array_size = unpack(unpack_header + 'I', packet_data[0:4])[0]
    packet_data = packet_data[4:]
    joint_names = []
    for i in range(0,array_size):
        string_len = unpack(unpack_header + 'I', packet_data[0:4])[0]
        joint_names.append(packet_data[4:4+string_len])
        joint_names[i] = joint_names[i].decode("utf-8")
        packet_data = packet_data[4+string_len:]

    ########################
    # Get the joint values #
    ########################

    # What size is this array?
    array_size = unpack(unpack_header + 'I', packet_data[0:4])[0]
    packet_data = packet_data[4:]
    joint_values = []
    for i in range(0,array_size):
        joint_values.append(unpack(unpack_header + 'd', packet_data[0:8])[0])
        packet_data = packet_data[8:]

    ###########################
    # Get the velocity values #
    ###########################

    # What size is this array?
    array_size = unpack(unpack_header + 'I', packet_data[0:4])[0]
    packet_data = packet_data[4:]
    joint_velocities = []
    for i in range(0,array_size):
        joint_velocities.append(unpack(unpack_header + 'd', packet_data[0:8])[0])
        packet_data = packet_data[8:]
        
    #########################
    # Get the effort values #
    #########################

    # What size is this array?
    array_size = unpack(unpack_header + 'I', packet_data[0:4])[0]
    packet_data = packet_data[4:]
    joint_efforts = []
    if array_size > 0:
        for i in range(0,array_size):
            joint_efforts.append(unpack(unpack_header + 'd', packet_data[0:8])[0])
            packet_data = packet_data[8:]
    else:
        joint_efforts = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        
    ###########################################
    # Insert all the data into the dictionary #
    ###########################################
    
    for idx, j in enumerate(joint_names):
        returnInfo[str(j) + "_value"] = joint_values[idx]
        returnInfo[str(j) + "_velocity"] = joint_velocities[idx]
        returnInfo[str(j) + "_effort"] = joint_efforts[idx]
    
    return returnInfo

def dissectBricsActuatorJointValueMsg(unpack_header, packet_data):
    
    # Clear the output dictionary, and add the msg type
    returnInfo = {'ros_msg_type': ROS_PACKET_TYPES[1]}    

    ros_pkt_len = unpack(unpack_header + 'I', packet_data[0:4])[0]
    returnInfo['ros_msg_len'] = str(ros_pkt_len)
    packet_data = packet_data[4:]

    # If our packet size is later than 3500, we can guess it's a false positive
    if ros_pkt_len > 3500:
        return ""

    originator_len = unpack(unpack_header + 'I', packet_data[0:4])[0]
    if originator_len > 0:
        returnInfo['ros_originator'] = str(packet_data[4:4+originator_len])
    packet_data = packet_data[4+originator_len:]

    description_len = unpack(unpack_header + 'I', packet_data[0:4])[0]
    if description_len > 0:
         returnInfo['ros_desription'] = str(packet_data[4:4+description_len])
    packet_data = packet_data[4+description_len:]

    #Strip away the QoS (not used)
    packet_data = packet_data[4:]

    # What size is this array?
    array_size = unpack(unpack_header + 'I', packet_data[0:4])[0]
    packet_data = packet_data[4:]

    #####################################################
    # Get the joint info and insert into the dictionary #
    #####################################################

    for i in range(0,array_size):
        packet_data = packet_data[8:]    #Strip the timestamp (not used)
        
        joint_uri_len = unpack(unpack_header + 'I', packet_data[0:4])[0]    #How long is the string?
        joint_uri = packet_data[4:4+joint_uri_len].decode("utf-8")
        returnInfo["ros_arm_num"] = 0
        if joint_uri.count("_2_") > 0 and returnInfo["ros_arm_num"] == 0:
            returnInfo["ros_arm_num"] = 2
            joint_uri = joint_uri.replace("_2_", "_")
        else:
            returnInfo["ros_arm_num"] = 1
        packet_data = packet_data[4+joint_uri_len:]    #Strip the string from the data

        joint_unit_len = unpack(unpack_header + 'I', packet_data[0:4])[0]    #How long is the string?
        returnInfo[str(joint_uri) + '_unit'] = packet_data[4:4+joint_unit_len].decode("utf-8")
        packet_data = packet_data[4+joint_unit_len:]    #Strip the string from the data

        returnInfo[str(joint_uri) + '_value'] = unpack(unpack_header + 'd', packet_data[0:8])[0]
        packet_data = packet_data[8:]    #Strip the value
    
    return returnInfo
    
    
    
def dissectDependencyMsg(unpack_header, packet_data):
    
    # Clear the output dictionary, and add the msg type
    returnInfo = {'ros_msg_type': ROS_PACKET_TYPES[3]}
    
    # Unpack the header
    ros_header = unpack(unpack_header + 'IIIII', packet_data[0:20])

    # If our packet size is larger than 3500, we can guess it's a false positive
    if ros_header[0] > 3500:
        return {}

    returnInfo['ros_msg_len'] = str(ros_header[0])
    returnInfo['ros_frame_id'] = str(ros_header[1])
    returnInfo['ros_time'] = str(ros_header[2]) + "." + str(ros_header[3])
    
    # Is there a sequence number?
    if ros_header[4] > 0:
        # If so, let's store the value
        returnInfo['ros_seq_num'] = str(packet_data[20:20+ros_header[4]])
    # Remove the ROS header
    packet_data = packet_data[20 + ros_header[4]:]
    
    depend_len = unpack(unpack_header + 'I', packet_data[0:4])[0]    # How long is the string?
    returnInfo['depend_string'] = packet_data[4:4+depend_len].decode("utf-8")
    packet_data = packet_data[4+depend_len:]    #Strip the string from the data
    returnInfo['depend_val'] = packet_data[0:1]
    
    return returnInfo
    
    
def dissectGripperMsg(unpack_header, d):
    # The gripper message is the same as the joint message, so let it handle the dissection
    returnInfo = dissectBricsActuatorJointValueMsg(unpack_header, d)
    # Rewrite the message type
    returnInfo['ros_msg_type'] = ROS_PACKET_TYPES[4]
    return returnInfo
    
    

# For now we are going to just discard this message type
def dissectDebugMsg(unpack_header, d):
    returnInfo = {'ros_msg_type': ROS_PACKET_TYPES[2]}
    return returnInfo
    
    
    
    
    
def dissectPacket(unpack_header, d):

    # Clear the foundMessages list (returned later)
    foundMessages = []
    
    # Is there data in this packet?
    while len(d) >= 4:
        # Anticipating that this is a ROS message, grab the first four
        # bytes, which should be the length of the packet
        msg_len = unpack(unpack_header + 'I', d[0:4])[0]
        # Is there data left in this packet?
        if msg_len > 0:
            # Iterate through the packet identifiers
            for rosIdentifier in ROS_PACKETS:
                # Determine the number of indices provided in the ROS_PACKETS list
                numIDXs = len(rosIdentifier) - 1
                # Clear the number of matches found
                matchesFound = 0
                # Iterate through each IDX to find a match
                for x in range(numIDXs):
                    currIdx = rosIdentifier[x+1][0]
                    currStr = rosIdentifier[x+1][1]
                    #print("\nCurr IDX = " + str(currIdx) + "\nCurr Str = " + str(currStr) + "\nData = " + str(d[currIdx:len(currStr)+currIdx]))
                    if d[currIdx:len(currStr)+currIdx] == currStr.encode():
                        matchesFound += 1
                    else:
                        break;
                # If the matches found equal the idx's and text provided, then
                # skip searching for the rest of the packet types
                if matchesFound == numIDXs:
                    # Process the packet based on the type found
                    if rosIdentifier[0] == 0:
                        # Send the data to the JointMsg dissector, and append the returned data
                        foundMessages.append(dissectJointStateMsg(unpack_header, d))
                    elif rosIdentifier[0] == 1:
                        # Send the data to the BricsMsg dissector, and append the returned data
                        foundMessages.append(dissectBricsActuatorJointValueMsg(unpack_header, d))
                    elif rosIdentifier[0] == 2:
                        foundMessages.append(dissectDebugMsg(unpack_header, d))
                    elif rosIdentifier[0] == 3:
                        foundMessages.append(dissectDependencyMsg(unpack_header, d))
                    elif rosIdentifier[0] == 4:
                        foundMessages.append(dissectGripperMsg(unpack_header, d))
                    break
            # Remove the message we just parsed.
            d = d[4+msg_len:]
            
        else:
            # Some messages may have padding, so remove it
            d = d[4:]
        
        
    return foundMessages  # Return the list of messages
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    