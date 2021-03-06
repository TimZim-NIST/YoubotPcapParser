#
# Author:       Timothy Zimmerman (timothy.zimmerman@nist.gov)
# Organization: National Institute of Standards and Technology
#               U.S. Department of Commerce
# License:      Public Domain
#
# Description:  
#

import sqlite3
from ast import literal_eval

conn = sqlite3.connect("unified_20150818-174114.db")
conn.row_factory = sqlite3.Row
c = conn.cursor()

try:
    c.execute('''CREATE INDEX seqNum ON packets ( shark_tcp_seq_num )''')
except:
    pass

try:
    c.execute('''CREATE INDEX md5 ON packets ( md5_hash )''')
except:
    pass

try:
    c.execute('''CREATE INDEX packets_id_idx ON packets ( id )''')
except:
    pass

try:
    print ("Creating md5 index on rosPackets table...", end='')
    c.execute('''CREATE INDEX rosmsg_md5 ON rosPackets ( md5_hash )''')
except:
    print (" already exists.")
    pass
else:
    print (" [DONE]")

try:
    c.execute('''CREATE INDEX parent_id_idx ON rosPackets ( parent_id )''')
except:
    pass

try:
    c.execute('''CREATE TABLE matchingPackets (\
                id INTEGER PRIMARY KEY AUTOINCREMENT, \
                packet_1_id INTEGER, packet_2_id INTEGER, \
                packet_1_time REAL, packet_2_time, delta_t REAL)''')
except:
    pass

try:
    c.execute('''CREATE TABLE misplacedPackets (\
                id INTEGER PRIMARY KEY AUTOINCREMENT, packet_id_1 INTEGER)''')
except:
    pass

try:
    c.execute('''CREATE TABLE ros_JointStateMessages (\
                id INTEGER PRIMARY KEY AUTOINCREMENT, \
                parent_id INTEGER, \
                ros_time REAL, \
                ros_frame_id TEXT, \
                ros_msg_len INTEGER, \
                ros_arm_num INTEGER, \
                arm_joint_1_value REAL, \
                arm_joint_2_value REAL, \
                arm_joint_3_value REAL, \
                arm_joint_4_value REAL, \
                arm_joint_5_value REAL, \
                gripper_finger_joint_l_value REAL, \
                gripper_finger_joint_r_value REAL, \
                arm_joint_1_velocity REAL, \
                arm_joint_2_velocity REAL, \
                arm_joint_3_velocity REAL, \
                arm_joint_4_velocity REAL, \
                arm_joint_5_velocity REAL, \
                gripper_finger_joint_l_velocity REAL, \
                gripper_finger_joint_r_velocity REAL, \
                arm_joint_1_effort REAL, \
                arm_joint_2_effort REAL, \
                arm_joint_3_effort REAL, \
                arm_joint_4_effort REAL, \
                arm_joint_5_effort REAL, \
                gripper_finger_joint_l_effort REAL, \
                gripper_finger_joint_r_effort REAL \
                )''')
except:
    pass

try:
    c.execute('''CREATE INDEX js_parent_id_idx ON ros_JointStateMessages ( parent_id )''')
except:
    pass

try:
    c.execute('''CREATE TABLE ros_BricsPositionMessages (\
                id INTEGER PRIMARY KEY AUTOINCREMENT, \
                parent_id INTEGER, \
                ros_msg_len INTEGER, \
                ros_arm_num INTEGER, \
                delta BOOLEAN, \
                arm_joint_1_value REAL, \
                arm_joint_2_value REAL, \
                arm_joint_3_value REAL, \
                arm_joint_4_value REAL, \
                arm_joint_5_value REAL, \
                arm_joint_1_unit TEXT, \
                arm_joint_2_unit TEXT, \
                arm_joint_3_unit TEXT, \
                arm_joint_4_unit TEXT, \
                arm_joint_5_unit TEXT  \
                )''')
except:
    pass

try:
    c.execute('''CREATE INDEX brics_index_1 ON ros_BricsPositionMessages ( delta, parent_id, ros_arm_num )''')
except:
    pass

try:
    c.execute('''CREATE TABLE ros_BricsGripperMessages (\
                id INTEGER PRIMARY KEY AUTOINCREMENT, \
                parent_id INTEGER, \
                ros_msg_len INTEGER, \
                ros_arm_num INTEGER, \
                gripper_finger_joint_l_value REAL, \
                gripper_finger_joint_r_value REAL, \
                gripper_finger_joint_l_unit TEXT, \
                gripper_finger_joint_r_unit TEXT \
                )''')
except:
    pass

try:
    c.execute('''CREATE TABLE ros_DependencyMessages (\
                id INTEGER PRIMARY KEY AUTOINCREMENT, \
                parent_id INTEGER, \
                ros_time REAL, \
                ros_frame_id TEXT, \
                ros_msg_len INTEGER, \
                depend_name TEXT, \
                depend_value INTEGER \
                )''')
except:
    pass

try:
    c.execute('''CREATE TABLE analyze_JointResponseTimes (\
                id INTEGER PRIMARY KEY AUTOINCREMENT, \
                brics_message_id INTEGER, \
                joint_state_message_id INTEGER, \
                delay REAL \
                )''')
except:
    pass


################################
### GATHER THE UNIQUE PACKETS ##
################################
#c.execute('''SELECT DISTINCT id, md5_hash FROM packets ORDER BY md5_hash''')
#distinct_hashes = c.fetchall()

##############################################################
### ATTEMPT TO MATCH ORIGINATOR PACKETS TO RECEIVED PACKETS ##
###             AND CALCULATE THE TIME-OF-FLIGHT            ##
##############################################################
#
#for md5 in distinct_hashes:
#    queryParams = (md5['md5_hash'],)
#    c.execute('''SELECT id, shark_timestamp FROM packets WHERE md5_hash = ? ORDER BY shark_timestamp ASC''', queryParams)
#    packets = c.fetchall()
#    if len(packets) == 2:
#        delta_t = abs(packets[0]['shark_timestamp'] - packets[1]['shark_timestamp'])
#        idTuple = (packets[0]['id'], packets[1]['id'], packets[0]['shark_timestamp'], packets[1]['shark_timestamp'], delta_t)
#        c.execute('''INSERT INTO matchingPackets VALUES (NULL,?,?,?,?,?)''', idTuple)
#    elif len(packets) == 1:
#        idTuple = (packets[0]['id'],)
#        c.execute('''INSERT INTO misplacedPackets VALUES (NULL,?)''', idTuple)
#    else:
#        raise Exception("Multiple sets of packets were found with the same MD5 hash: " + str(len(packets)))
#       
#conn.commit()

###################################
### DISSECT THE ROS MESSAGE DATA ##
###################################
#
#c.execute('''SELECT DISTINCT md5_hash FROM rosPackets ORDER BY id ASC''')
#distinct_hashes = c.fetchall()
#
#for md5 in distinct_hashes:
#    queryParams = (md5['md5_hash'],)
#    c.execute('''SELECT parent_id, ros_msg_tuple FROM rosPackets WHERE md5_hash = ?''', queryParams)
#    rosMsg = c.fetchone()
#    rosTuple = literal_eval(rosMsg['ros_msg_tuple'])
#    #DEBUG#print ("MSG #" + str(rosMsg['parent_id']) + " type: " + rosTuple['ros_msg_type'])
#    
#    #########################
#    ## JOINT STATE MESSAGE ##
#    #########################
#    if rosTuple['ros_msg_type'] == "JointStateMsg":
#        try:
#            if 'arm_joint_1_value' in rosTuple:
#                jointStateTuple = ( rosMsg['parent_id'], \
#                                    rosTuple['ros_time'], \
#                                    rosTuple['ros_frame_id'], \
#                                    rosTuple['ros_msg_len'], \
#                                    1, \
#                                    rosTuple['arm_joint_1_value'], \
#                                    rosTuple['arm_joint_2_value'], \
#                                    rosTuple['arm_joint_3_value'], \
#                                    rosTuple['arm_joint_4_value'], \
#                                    rosTuple['arm_joint_5_value'], \
#                                    rosTuple['gripper_finger_joint_l_value'], \
#                                    rosTuple['gripper_finger_joint_r_value'], \
#                                    rosTuple['arm_joint_1_velocity'], \
#                                    rosTuple['arm_joint_2_velocity'], \
#                                    rosTuple['arm_joint_3_velocity'], \
#                                    rosTuple['arm_joint_4_velocity'], \
#                                    rosTuple['arm_joint_5_velocity'], \
#                                    rosTuple['gripper_finger_joint_l_velocity'], \
#                                    rosTuple['gripper_finger_joint_r_velocity'], \
#                                    rosTuple['arm_joint_1_effort'], \
#                                    rosTuple['arm_joint_2_effort'], \
#                                    rosTuple['arm_joint_3_effort'], \
#                                    rosTuple['arm_joint_4_effort'], \
#                                    rosTuple['arm_joint_5_effort'], \
#                                    rosTuple['gripper_finger_joint_l_effort'], \
#                                    rosTuple['gripper_finger_joint_r_effort']  )
#            elif 'arm_2_joint_1_value' in rosTuple:
#                jointStateTuple = ( rosMsg['parent_id'], \
#                                    rosTuple['ros_time'], \
#                                    rosTuple['ros_frame_id'], \
#                                    rosTuple['ros_msg_len'], \
#                                    2, \
#                                    rosTuple['arm_2_joint_1_value'], \
#                                    rosTuple['arm_2_joint_2_value'], \
#                                    rosTuple['arm_2_joint_3_value'], \
#                                    rosTuple['arm_2_joint_4_value'], \
#                                    rosTuple['arm_2_joint_5_value'], \
#                                    rosTuple['gripper_2_finger_joint_l_value'], \
#                                    rosTuple['gripper_2_finger_joint_r_value'], \
#                                    rosTuple['arm_2_joint_1_velocity'], \
#                                    rosTuple['arm_2_joint_2_velocity'], \
#                                    rosTuple['arm_2_joint_3_velocity'], \
#                                    rosTuple['arm_2_joint_4_velocity'], \
#                                    rosTuple['arm_2_joint_5_velocity'], \
#                                    rosTuple['gripper_2_finger_joint_l_velocity'], \
#                                    rosTuple['gripper_2_finger_joint_r_velocity'], \
#                                    rosTuple['arm_2_joint_1_effort'], \
#                                    rosTuple['arm_2_joint_2_effort'], \
#                                    rosTuple['arm_2_joint_3_effort'], \
#                                    rosTuple['arm_2_joint_4_effort'], \
#                                    rosTuple['arm_2_joint_5_effort'], \
#                                    rosTuple['gripper_2_finger_joint_l_effort'], \
#                                    rosTuple['gripper_2_finger_joint_r_effort']  )
#        except KeyError as e:
#            print("ROS Message #" + str(rosMsg['parent_id']) + " KeyError: " + str(e))
#        else:
#            c.execute('''INSERT INTO ros_JointStateMessages VALUES (NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', jointStateTuple)
#            
#    ############################
#    ## BRICS POSITION MESSAGE ##
#    ############################
#    elif rosTuple['ros_msg_type'] == "BricsPositionMsg":
#        try:
#            bricsTuple = (  rosMsg['parent_id'], \
#                            rosTuple['ros_msg_len'], \
#                            rosTuple['ros_arm_num'], \
#                            rosTuple['arm_joint_1_value'], \
#                            rosTuple['arm_joint_2_value'], \
#                            rosTuple['arm_joint_3_value'], \
#                            rosTuple['arm_joint_4_value'], \
#                            rosTuple['arm_joint_5_value'], \
#                            rosTuple['arm_joint_1_unit'],  \
#                            rosTuple['arm_joint_2_unit'],  \
#                            rosTuple['arm_joint_3_unit'],  \
#                            rosTuple['arm_joint_4_unit'],  \
#                            rosTuple['arm_joint_5_unit']   )
#        except KeyError as e:
#            print("ROS Message #" + str(rosMsg['parent_id']) + " KeyError: " + str(e))
#        else:
#            c.execute('''INSERT INTO ros_BricsPositionMessages VALUES (NULL,?,?,?,0,?,?,?,?,?,?,?,?,?,?)''', bricsTuple)
#           
#    #####################
#    ## GRIPPER MESSAGE ##
#    #####################
#    elif rosTuple['ros_msg_type'] == "GripperMsg":
#        try:
#            gripperTuple = (    rosMsg['parent_id'],                      \
#                                rosTuple['ros_msg_len'],                  \
#                                rosTuple['ros_arm_num'],                  \
#                                rosTuple['gripper_finger_joint_l_value'], \
#                                rosTuple['gripper_finger_joint_r_value'], \
#                                rosTuple['gripper_finger_joint_l_unit'],  \
#                                rosTuple['gripper_finger_joint_r_unit']   )
#        except KeyError as e:
#            print("ROS Message #" + str(rosMsg['parent_id']) + " KeyError: " + str(e))
#        else:
#            c.execute('''INSERT INTO ros_BricsGripperMessages VALUES (NULL,?,?,?,?,?,?,?)''', gripperTuple)
#
#    ########################
#    ## DEPENDENCY MESSAGE ##
#    ########################
#    elif rosTuple['ros_msg_type'] == "DependencyMsg":
#        #print(rosTuple)
#        try:
#            dependTuple = (     rosMsg['parent_id'],                      \
#                                rosTuple['ros_time'],                     \
#                                rosTuple['ros_frame_id'],                 \
#                                rosTuple['ros_msg_len'],                  \
#                                rosTuple['depend_string'],                \
#                                rosTuple['depend_val']                    )
#        except KeyError as e:
#            print("ROS Message #" + str(rosMsg['parent_id']) + " KeyError: " + str(e))
#        else:
#            c.execute('''INSERT INTO ros_DependencyMessages VALUES (NULL,?,?,?,?,?,?)''', dependTuple)
#        
#conn.commit()

#################################
### MARK UNIQUE BRICS MESSAGES ##
#################################
#for arm_num in range(1,3):
#    params = (arm_num,)
#    c.execute('''SELECT ros_BricsPositionMessages.id, arm_joint_1_value, arm_joint_2_value, \
#                arm_joint_3_value, arm_joint_4_value, arm_joint_5_value FROM ros_BricsPositionMessages \
#                INNER JOIN packets WHERE ros_BricsPositionMessages.parent_id = packets.id AND \
#                ros_BricsPositionMessages.ros_arm_num = ? ORDER BY packets.shark_timestamp ASC''', params)
#    brics_messages = c.fetchall()
#    
#    feedback = {'joint_1': 0, 'joint_2': 0, 'joint_3': 0, 'joint_4': 0, 'joint_5': 0}
#    
#    for d in brics_messages:
#        this_id = (d['id'],)
#        if feedback['joint_1'] != d['arm_joint_1_value'] or \
#           feedback['joint_2'] != d['arm_joint_2_value'] or \
#           feedback['joint_3'] != d['arm_joint_3_value'] or \
#           feedback['joint_4'] != d['arm_joint_4_value'] or \
#           feedback['joint_5'] != d['arm_joint_5_value']:
#            c.execute('''UPDATE ros_BricsPositionMessages SET delta = 1 WHERE id = ?''', this_id)
#            feedback['joint_1'] = d['arm_joint_1_value']
#            feedback['joint_2'] = d['arm_joint_2_value']
#            feedback['joint_3'] = d['arm_joint_3_value']
#            feedback['joint_4'] = d['arm_joint_4_value']
#            feedback['joint_5'] = d['arm_joint_5_value']
#        else:
#            c.execute('''UPDATE ros_BricsPositionMessages SET delta = 0 WHERE id = ?''', this_id)
#        
#conn.commit()

#######################################################
## FIND THE DELTA t FROM BRICS MESSAGE TO MOVE START ##
#######################################################

for arm_num in range(1,3):
    # Get the unique Brics messages from the database
    params = (arm_num,)
    c.execute('''SELECT parent_id, shark_timestamp from ros_BricsPositionMessages \
                 INNER JOIN packets WHERE ros_BricsPositionMessages.parent_id = packets.id \
                 AND ros_BricsPositionMessages.delta = 1 AND ros_BricsPositionMessages.ros_arm_num = ? \
                 ORDER BY ros_BricsPositionMessages.parent_id ASC''', params)
    brics_messages = c.fetchall()
    
    # Cycle through each unique Brics message
    for d in brics_messages:
        
        # Grab the brics message time for later delta time calculation
        brics_packet_time = d['shark_timestamp']
        
        # Get the next unique Brics message ID#
        params = (d['parent_id'], arm_num)
        c.execute('''SELECT parent_id from ros_BricsPositionMessages WHERE delta = 1 \
                     AND parent_id > ? AND ros_arm_num = ? LIMIT 1''', params)
        next_id = c.fetchone()
        
        # If there is a Brics message after the current one (d), we need to get all the
        # other joint state messages that occured between d and the next unique Brics 
        # message (next_id)
        if next_id != None:
            params = (arm_num,d['parent_id'], next_id['parent_id'])
            c.execute('''SELECT parent_id, arm_joint_1_value, arm_joint_2_value, \
                         arm_joint_3_value, arm_joint_4_value, arm_joint_5_value, \
                         shark_timestamp FROM ros_JointStateMessages INNER JOIN packets \
                         WHERE ros_JointStateMessages.parent_id = packets.id \
                         AND ros_JointStateMessages.ros_arm_num = ? \
                         AND ros_JointStateMessages.parent_id > ? \
                         AND ros_JointStateMessages.parent_id < ?''', params)
            jointstate_packets = c.fetchall()
            
            # Store the current position for comparison
            current_pos = ( 0, \
                            jointstate_packets[0]['arm_joint_1_value'], \
                            jointstate_packets[0]['arm_joint_2_value'], \
                            jointstate_packets[0]['arm_joint_3_value'], \
                            jointstate_packets[0]['arm_joint_4_value'], \
                            jointstate_packets[0]['arm_joint_5_value'] )
                            
            # Movement tolerance of 1 degree 
            move_tolerance = 0.0174 
                           
            # For each packet of this move, compare the new joint state to the
            # first joint state, and if any are greater than the tolerance, 
            # calculate the delta time between the Brics message, and the start 
            # of the move and store it in the DB
            for m in jointstate_packets:
                # We con't compare to joint #5 because one of the robots currently has encoder issues
                if abs(m['arm_joint_1_value'] - current_pos[1]) > move_tolerance or \
                   abs(m['arm_joint_2_value'] - current_pos[2]) > move_tolerance or \
                   abs(m['arm_joint_3_value'] - current_pos[3]) > move_tolerance or \
                   abs(m['arm_joint_4_value'] - current_pos[4]) > move_tolerance    :
                       delta_time = abs(m['shark_timestamp'] - brics_packet_time)
                       #print("Delta time = " + str(delta_time*1000)+ " milliseconds between Brics packet " + str(d['parent_id']) + " and joint state packet " + str(m['parent_id']))
                       
                       # Insert this data into the DB analyze_JointResponseTimes
                       responseTuple = (d['parent_id'], m['parent_id'], delta_time)
                       c.execute('''INSERT INTO analyze_JointResponseTimes VALUES (NULL,?,?,?)''', responseTuple)
                       break

conn.commit()       
    
print ("[ANALYSIS COMPLETE]")

# Now we have a database and a PCAP file with the same data, close everything!
conn.close()










