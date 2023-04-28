import copy
from data.trace import Trace
from utils.utils import Utils

class MessageModificator:

    def __init__(self, trace, attack) -> None:

        self.trace:Trace = trace

        self.type: str = attack['type']
        self.start_time_offset = attack['start']
        self.end_time_offset = attack['end']
        self.start_bit = attack['start_bit']
        self.end_bit = attack['end_bit']
        self.target_id = attack['id']

        self.logger = Utils.get_logger()
    

    def modify_messages_CONST(self):
        
        malicious_trace:Trace = copy.deepcopy(self.trace)

        start_timestamp = malicious_trace.get_trace_length() * self.start_time_offset
        end_timestamp = malicious_trace.get_trace_length() * self.end_time_offset

        last_attack_time = 0
        first_attack_time = 0

        malicious_content = []
        for message in malicious_trace.messages:
            if message.get_timestamp_in_seconds() >= start_timestamp and message.id == int(self.target_id, 16):
                # find the first speed message after start time and save speed signal value
                malicious_content = message.data[1:3]
                break


        self.logger.debug(f"Modifying message data to this malicious value: {int.from_bytes(message.data[1:3], 'big') / 100}")

        for message in malicious_trace.messages:

            # test if we are within the attack range
            if start_timestamp > message.get_timestamp_in_seconds():
                continue
            if message.get_timestamp_in_seconds() > end_timestamp:
                break

            if message.id == int(self.target_id, 16):
                message.is_malicious = 1
                message.data[self.start_bit:self.end_bit] = malicious_content
                
                last_attack_time = message.get_timestamp_in_seconds()
                if first_attack_time == 0:
                    first_attack_time = last_attack_time

        
        self.logger.debug(f"First attack time: {first_attack_time}")
        self.logger.debug(f"Last attack time: {last_attack_time}")
        malicious_trace.first_attack_time = first_attack_time
        malicious_trace.last_attack_time = last_attack_time
        malicious_trace.malicious_id = hex(int(self.target_id, 16))

        return malicious_trace


    def modify_messages_REPLAY(self):
        
        malicious_trace:Trace = copy.deepcopy(self.trace)

        copy_start_offset = self.start_time_offset - (self.end_time_offset - self.start_time_offset)
        if copy_start_offset < 0:
            copy_start_offset = 0
        start_of_copy_timestamp = malicious_trace.get_trace_length() * copy_start_offset
        start_timestamp = malicious_trace.get_trace_length() * self.start_time_offset

        malicious_trace.first_attack_time = 0
        malicious_trace.last_attack_time = 0

        self.logger.debug(f"Starting the copy sequence of the original data for id {self.target_id}.")
        malicious_contents = []
        for message in malicious_trace.messages:
            # test if we are within the copy range
            if message.get_timestamp_in_seconds() < start_of_copy_timestamp:
                continue
            if message.get_timestamp_in_seconds() > start_timestamp:
                break
            if message.id == int(self.target_id, 16): 
                malicious_contents.append(message.data[self.start_bit:self.end_bit])


        self.logger.debug(f"Starting the modification sequence of the attack for id {self.target_id}.")
        copy_index = 0
        copy_length = len(malicious_contents)
        for message in malicious_trace.messages:

            # test if we are within the attack range
            if start_timestamp > message.get_timestamp_in_seconds():
                continue
            if copy_index >= copy_length:
                break

            if message.id == int(self.target_id, 16):
                message.is_malicious = 1
                #message.data[1:3] = malicious_content
                message.data[self.start_bit:self.end_bit] = malicious_contents[copy_index]
                copy_index += 1
                
                malicious_trace.last_attack_time = message.get_timestamp_in_seconds()
                if malicious_trace.first_attack_time == 0:
                    malicious_trace.first_attack_time = malicious_trace.last_attack_time

        
        self.logger.debug(f"First attack time: {malicious_trace.first_attack_time}")
        self.logger.debug(f"Last attack time: {malicious_trace.last_attack_time}")
        malicious_trace.malicious_id = hex(int(self.target_id, 16))

        return malicious_trace


    def modify_messages_ADD_INCR(self):
        
        malicious_trace:Trace = copy.deepcopy(self.trace)

        start_timestamp = malicious_trace.get_trace_length() * self.start_time_offset
        end_timestamp = malicious_trace.get_trace_length() * self.end_time_offset

        last_attack_time = 0
        first_attack_time = 0

        malicious_content = []
        for message in malicious_trace.messages:
            if message.get_timestamp_in_seconds() >= start_timestamp and message.id == int(self.target_id, 16):
                # find the first speed message after start time and save speed signal value
                malicious_content = message.data[self.start_bit:self.end_bit]
                break


        self.logger.debug(f"Modifying message data starting with this malicious value: {int.from_bytes(message.data[1:3], 'big') / 100} and then increasing it continiously.")

        for message in malicious_trace.messages:

            # test if we are within the attack range
            if start_timestamp > message.get_timestamp_in_seconds():
                continue
            if message.get_timestamp_in_seconds() > end_timestamp:
                break

            if message.id == int(self.target_id, 16):
                message.is_malicious = 1
                message.data[self.start_bit:self.end_bit] = malicious_content

                if malicious_content[1] < 255:
                    malicious_content[1] += 1
                else:
                    if malicious_content[0] < 255:
                        malicious_content[0] += 1
                        malicious_content[1] = 0
                
                last_attack_time = message.get_timestamp_in_seconds()
                if first_attack_time == 0:
                    first_attack_time = last_attack_time

        
        self.logger.debug(f"First attack time: {first_attack_time}")
        self.logger.debug(f"Last attack time: {last_attack_time}")
        malicious_trace.first_attack_time = first_attack_time
        malicious_trace.last_attack_time = last_attack_time
        malicious_trace.malicious_id = hex(int(self.target_id, 16))

        return malicious_trace


    def modify_messages_ADD_DECR(self):
        
        malicious_trace:Trace = copy.deepcopy(self.trace)

        start_timestamp = malicious_trace.get_trace_length() * self.start_time_offset
        end_timestamp = malicious_trace.get_trace_length() * self.end_time_offset

        last_attack_time = 0
        first_attack_time = 0

        malicious_content = []
        for message in malicious_trace.messages:
            if message.get_timestamp_in_seconds() >= start_timestamp and message.id == int(self.target_id, 16):  # malicious_trace.speed_id
                # find the first speed message after start time and save speed signal value
                malicious_content = message.data[self.start_bit:self.end_bit]
                break


        self.logger.debug(f"Modifying message data starting with this malicious value: {int.from_bytes(message.data[1:3], 'big') / 100} and then decreasing it continiously.")

        for message in malicious_trace.messages:

            # test if we are within the attack range
            if start_timestamp > message.get_timestamp_in_seconds():
                continue
            if message.get_timestamp_in_seconds() > end_timestamp:
                break

            if message.id == int(self.target_id, 16):
                message.is_malicious = 1
                #message.data[1:3] = malicious_content
                message.data[self.start_bit:self.end_bit] = malicious_content

                # Update attack value. Only works for 2 byte attacks!
                if malicious_content[1] > 0:
                    malicious_content[1] -= 1
                else:
                    if malicious_content[0] > 0:
                        malicious_content[0] -= 1
                        malicious_content[1] = 255
                
                last_attack_time = message.get_timestamp_in_seconds()
                if first_attack_time == 0:
                    first_attack_time = last_attack_time

        
        self.logger.debug(f"First attack time: {first_attack_time}")
        self.logger.debug(f"Last attack time: {last_attack_time}")
        malicious_trace.first_attack_time = first_attack_time
        malicious_trace.last_attack_time = last_attack_time
        malicious_trace.malicious_id = hex(int(self.target_id, 16))

        return malicious_trace


    def modify_messages_POS_OFFSET(self):
        
        malicious_trace:Trace = copy.deepcopy(self.trace)

        start_timestamp = malicious_trace.get_trace_length() * self.start_time_offset
        end_timestamp = malicious_trace.get_trace_length() * self.end_time_offset

        malicious_trace.first_attack_time = 0
        malicious_trace.last_attack_time = 0

        malicious_constant = 1.2
        malicious_content = [0,0]
        for message in malicious_trace.messages:
            if message.get_timestamp_in_seconds() >= start_timestamp and message.id == int(self.target_id, 16):
                # find the first speed message after start time and save speed signal value
                malicious_content[0] = abs(message.data[self.start_bit] - int(message.data[self.start_bit] * malicious_constant))
                malicious_content[1] = abs(message.data[self.start_bit+1] - int(message.data[self.start_bit+1] * malicious_constant))
                break

        self.logger.debug(f"Modifying message data: offsetting it with this malicious value: {malicious_content}")


        for message in malicious_trace.messages:

            # test if we are within the attack range
            if start_timestamp > message.get_timestamp_in_seconds():
                continue
            if message.get_timestamp_in_seconds() > end_timestamp:
                break

            if message.id == int(self.target_id, 16):
                message.is_malicious = 1
                message.data[self.start_bit] += malicious_content[0]
                message.data[self.start_bit+1] += malicious_content[1]

                # check if after the addition the result fits into a byte
                if message.data[self.start_bit+1] >= 255 and message.data[self.start_bit] <= 255:
                    message.data[self.start_bit+1] = 0
                    message.data[self.start_bit] += 1
                if message.data[self.start_bit] > 255:
                    message.data[self.start_bit] = 255
                    message.data[self.start_bit+1] = 255
                
                malicious_trace.last_attack_time = message.get_timestamp_in_seconds()
                if malicious_trace.first_attack_time == 0:
                    malicious_trace.first_attack_time = malicious_trace.last_attack_time

        self.logger.debug(f"First attack time: {malicious_trace.first_attack_time}")
        self.logger.debug(f"Last attack time: {malicious_trace.last_attack_time}")
        malicious_trace.malicious_id = hex(int(self.target_id, 16))

        return malicious_trace

    
    def modify_messages_NEG_OFFSET(self):
        
        malicious_trace:Trace = copy.deepcopy(self.trace)

        start_timestamp = malicious_trace.get_trace_length() * self.start_time_offset
        end_timestamp = malicious_trace.get_trace_length() * self.end_time_offset

        malicious_trace.first_attack_time = 0
        malicious_trace.last_attack_time = 0

        malicious_constant = 0.8
        malicious_content = [0,0]
        for message in malicious_trace.messages:
            if message.get_timestamp_in_seconds() >= start_timestamp and message.id == int(self.target_id, 16):
                # find the first speed message after start time and save speed signal value
                malicious_content[0] = message.data[self.start_bit] - int(message.data[self.start_bit] * malicious_constant)
                malicious_content[1] = message.data[self.start_bit+1] - int(message.data[self.start_bit+1] * malicious_constant)
                break

        self.logger.debug(f"Modifying message data: offsetting it with this malicious value: {malicious_content}")

        for message in malicious_trace.messages:

            # test if we are within the attack range
            if start_timestamp > message.get_timestamp_in_seconds():
                continue
            if message.get_timestamp_in_seconds() > end_timestamp:
                break

            if message.id == int(self.target_id, 16):
                message.is_malicious = 1
                message.data[self.start_bit] -= malicious_content[0]
                message.data[self.start_bit+1] -= malicious_content[1]

                # check if after the addition the result fits into a byte
                if message.data[self.start_bit+1] < 0 and message.data[self.start_bit] >= 0:
                    message.data[self.start_bit+1] = 255
                    message.data[self.start_bit] -= 1
                if message.data[self.start_bit] < 0:
                    message.data[self.start_bit] = 0
                    message.data[self.start_bit+1] = 0
                
                malicious_trace.last_attack_time = message.get_timestamp_in_seconds()
                if malicious_trace.first_attack_time == 0:
                    malicious_trace.first_attack_time = malicious_trace.last_attack_time

        self.logger.debug(f"First attack time: {malicious_trace.first_attack_time}")
        self.logger.debug(f"Last attack time: {malicious_trace.last_attack_time}")
        malicious_trace.malicious_id = hex(int(self.target_id, 16))

        return malicious_trace