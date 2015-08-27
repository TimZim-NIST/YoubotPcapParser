#
# Author:       Tim Zimmerman (timothy.zimmerman@nist.gov)
# Organization: National Institute of Standards and Technology
#               U.S. Department of Commerce
# License:      Public Domain
#
# Description:
#   Class to make searching for unique IDs in received packets simpler
#

from string import *
from struct import *

class uniqueID:

    def __init__(self, ID, upid, pos):
        self.ID = ID
        self.uPID = upid.encode()
        self.pos = pos
        self.len = (len(upid) + pos)
        
    def get_uPID(self):
        return self.uPID

    def getPos(self):
        return self.pos

    def getLen(self):
        return self.len

    def getID(self):
        return self.ID


def dissectJointStateMsg(unpack_header, packet_data):
    ros_header = unpack(unpack_header + 'IIIII', packet_data[0:20])

    # If our packet size is larger than 3500, we can guess it's a false positive
    if ros_header[0] > 3500:
        return ""

    dissection_string = "ROS Message Len: " + str(ros_header[0]) + "\n"
    dissection_string += "ROS Frame ID: " + str(ros_header[1]) + "\n"
    dissection_string += "ROS Time: " + str(ros_header[2]) + "." + str(ros_header[3]) + "\n"
    
    # Is there a frameID string?
    # TODO: I don't think this is actually a string... but we will leave
    #       it like this for now, since our packets do not use this field
    if ros_header[4] > 0:
        # If so, let's store the value
        ros_frame_id = packet_data[20:20+ros_header[4]]
        #print ("ROS FrameID Str Len: " + str(ros_header[4]))
        dissection_string += "ROS FrameID: " + str(ros_frame_id) + "\n"
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

    #########################
    # Get the effort values #
    #########################

    # What size is this array?
    array_size = unpack(unpack_header + 'I', packet_data[0:4])[0]
    packet_data = packet_data[4:]

    joint_effort = []
    for i in range(0,array_size):
        joint_effort.append(unpack(unpack_header + 'd', packet_data[0:8])[0])
        packet_data = packet_data[8:]

    dissection_string += "ROS Joint Names: " + str(joint_names) + "\n"
    dissection_string += "ROS Joint Values: " + str(joint_values) + "\n"
    dissection_string += "ROS Joint Effort: " + str(joint_effort) + "\n"

    return dissection_string



def dissectBricsActuatorJointValueMsg(unpack_header, packet_data):

    ros_pkt_len = unpack(unpack_header + 'I', packet_data[0:4])[0]
    dissection_string = "ROS Packet Len: " + str(ros_pkt_len) + "\n"
    packet_data = packet_data[4:]

    # If our packet size is later than 3500, we can guess it's a false positive
    if ros_pkt_len > 3500:
        return ""

    originator_len = unpack(unpack_header + 'I', packet_data[0:4])[0]
    if originator_len > 0:
        ros_originator = packet_data[4:4+originator_len]
    packet_data = packet_data[4+originator_len:]

    description_len = unpack(unpack_header + 'I', packet_data[0:4])[0]
    if description_len > 0:
        ros_description = packet_data[4:4+description_len]
    packet_data = packet_data[4+description_len:]

    #Strip away the QoS (not used)
    packet_data = packet_data[4:]

    # What size is this array?
    array_size = unpack(unpack_header + 'I', packet_data[0:4])[0]
    packet_data = packet_data[4:]

    ######################
    # Get the joint info #
    ######################

    joint_uri = []
    joint_value = []
    joint_unit = []

    for i in range(0,array_size):
        packet_data = packet_data[8:] #Strip the timestamp (not used)
        
        joint_uri_len = unpack(unpack_header + 'I', packet_data[0:4])[0]    #How long is the string?
        joint_uri.append(packet_data[4:4+joint_uri_len])     #Put the string in the array
        joint_uri[i] = joint_uri[i].decode("utf-8")         #Decode it
        packet_data = packet_data[4+joint_uri_len:]         #Strip the string from the data

        joint_unit_len = unpack(unpack_header + 'I', packet_data[0:4])[0]    #How long is the string?
        joint_unit.append(packet_data[4:4+joint_unit_len])    #Put the string in the array
        joint_unit[i] = joint_unit[i].decode("utf-8")       #Decode it
        packet_data = packet_data[4+joint_unit_len:]        #Strip the string from the data

        joint_value.append(unpack(unpack_header + 'd', packet_data[0:8])[0])
        packet_data = packet_data[8:] #Strip the value

    dissection_string += "ROS Joint Names: " + str(joint_uri) + "\n"
    dissection_string += "ROS Joint Values: " + str(joint_value) + "\n"
    dissection_string += "ROS Joint Units: " + str(joint_unit) + "\n"
    
    return dissection_string

