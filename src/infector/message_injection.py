import time
import subprocess
import copy
from typing import List
from data.message import Message
from data.trace import Trace
from utils.utils import Utils
from filemanager.trace_printer import LinuxCompatibleFilePrinter


class MessageInjector:

    def __init__(self, trace, attack, second_attack = None) -> None:

        self.trace:Trace = trace

        self.type: str = attack['type']
        
        self.start_offset = attack['start']
        self.end_offset = attack['end']
        attack['trace_length'] = self.trace.get_trace_length()
        self.start_timestamp = attack['trace_length'] * self.start_offset
        self.end_timestamp = attack['trace_length'] * self.end_offset        
        attack['first_attack_time'] = self.start_timestamp
        attack['last_attack_time'] = self.end_timestamp
        
        self.start_bit = attack['start_bit']
        self.end_bit = attack['end_bit']
        self.attack_target_id = int(attack['id'], 16)
        self.attack_inter_message_time = attack['attack_inter_message_time']
        self.attack = attack

        # Second attack parameters
        self.second_attack = None
        if second_attack:
            self.second_attack = second_attack

        self.logger = Utils.get_logger()
        self.config = Utils.get_config()

        self.message_shift_conter = 0

        self.messages_to_inject: List[Message] = []
        self.trace_name = None
        self.filename_log = attack['filename_log']
        self.injected_message_filename = self.attack['output'] + self.attack["filename"] + "-inj-messages.log"
    

    def load_attack_data(self, attack):
        self.type: str = attack['type']
        
        self.start_offset = attack['start']
        self.end_offset = attack['end']
        self.start_timestamp = self.trace.get_trace_length() * self.start_offset
        self.end_timestamp = self.trace.get_trace_length() * self.end_offset        
        attack['first_attack_time'] = self.start_timestamp
        attack['last_attack_time'] = self.end_timestamp
        
        self.start_bit = attack['start_bit']
        self.end_bit = attack['end_bit']
        self.attack_target_id = int(attack['id'], 16)
        self.attack_inter_message_time = attack['attack_inter_message_time']
        self.attack = attack


    def generate_messages_to_inject(self):
         # Generate malicious messages to inject into traffic
        match self.type:
            case "CONST":
                self.generate_messages_to_inject_CONST()
            case "ADD-INCR":
                self.generate_messages_to_inject_ADD_INCR()
            case "ADD-DECR":
                self.generate_messages_to_inject_ADD_DECR()
            case "POS-OFFSET":
                self.generate_messages_to_inject_POS_OFFSET()
            case "NEG-OFFSET":
                self.generate_messages_to_inject_NEG_OFFSET()
            case "REPLAY":
                self.generate_messages_to_inject_REPLAY()
            case _:
                raise Exception("Injection attack type not found!")

        if self.second_attack:
            self.load_attack_data(self.second_attack)
            match self.type:
                case "CONST":
                    self.generate_messages_to_inject_CONST()
                case "ADD-INCR":
                    self.generate_messages_to_inject_ADD_INCR()
                case "ADD-DECR":
                    self.generate_messages_to_inject_ADD_DECR()
                case "POS-OFFSET":
                    self.generate_messages_to_inject_POS_OFFSET()
                case "NEG-OFFSET":
                    self.generate_messages_to_inject_NEG_OFFSET()
                case "REPLAY":
                    self.generate_messages_to_inject_REPLAY()
                case _:
                    raise Exception("Injection attack type not found!")

            # order messages by timestamp
            self.messages_to_inject.sort(key=lambda x: x.timestamp, reverse=False)
            self.load_attack_data(self.attack)

        # Save generated messages to file
        LinuxCompatibleFilePrinter(self.injected_message_filename).write_messages_list(self.messages_to_inject)


    def generate_messages_to_inject_CONST(self):
        
        self.logger.debug(f"Generating attack trace with CONST message injection attack. From: {self.start_offset} until: {self.end_offset}")

        original_message = next(m for m in self.trace.messages if m.get_timestamp_in_seconds() > self.start_timestamp and m.id == self.attack_target_id)
        malicious_message_template = copy.deepcopy(original_message)
        
        while malicious_message_template.get_timestamp_in_seconds() < self.end_timestamp:
            self.messages_to_inject.append(copy.deepcopy(malicious_message_template))
            malicious_message_template.set_timestamp_from_seconds(malicious_message_template.get_timestamp_in_seconds() + self.attack_inter_message_time)


    def generate_messages_to_inject_ADD_INCR(self):

        self.logger.debug(f"Generating attack trace with ADD-INCR message injection attack. From: {self.start_offset} until: {self.end_offset}")

        original_message = next(m for m in self.trace.messages if m.get_timestamp_in_seconds() > self.start_timestamp and m.id == self.attack_target_id)
        malicious_message_template = copy.deepcopy(original_message)
        
        while malicious_message_template.get_timestamp_in_seconds() < self.end_timestamp:
            self.messages_to_inject.append(copy.deepcopy(malicious_message_template))
            malicious_message_template.set_timestamp_from_seconds(malicious_message_template.get_timestamp_in_seconds() + self.attack_inter_message_time)
            
            # increment signal value for next iteration
            signal = int.from_bytes(malicious_message_template.data[self.start_bit:self.end_bit], 'big')
            if signal < (2 ** (8 * (self.end_bit - self.start_bit)) - 1):
                signal += 1
                malicious_message_template.data[self.start_bit:self.end_bit] = list(signal.to_bytes(self.end_bit - self.start_bit, 'big'))


    def generate_messages_to_inject_ADD_DECR(self):
        
        self.logger.debug(f"Generating attack trace with ADD-DECR message injection attack. From: {self.start_offset} until: {self.end_offset}")

        original_message = next(m for m in self.trace.messages if m.get_timestamp_in_seconds() > self.start_timestamp and m.id == self.attack_target_id)
        malicious_message_template = copy.deepcopy(original_message)
        
        while malicious_message_template.get_timestamp_in_seconds() < self.end_timestamp:
            self.messages_to_inject.append(copy.deepcopy(malicious_message_template))
            malicious_message_template.set_timestamp_from_seconds(malicious_message_template.get_timestamp_in_seconds() + self.attack_inter_message_time)
            
            # increment signal value for next iteration
            signal = int.from_bytes(malicious_message_template.data[self.start_bit:self.end_bit], 'big')
            if signal > 0:
                signal -= 1
                malicious_message_template.data[self.start_bit:self.end_bit] = list(signal.to_bytes(self.end_bit - self.start_bit, 'big'))

            
    def generate_messages_to_inject_POS_OFFSET(self):
        
        self.logger.debug(f"Generating attack trace with POS-OFFSET message injection attack. From: {self.start_offset} until: {self.end_offset}")

        malicious_trace:Trace = copy.deepcopy(self.trace)

        # Calculate intermessage time
        relevant_messages:List[Message] = list(filter(lambda m: m.id == self.attack_target_id, malicious_trace.messages))
        differences = []
        for i in range(0, len(relevant_messages) - 1):
            differences.append(relevant_messages[i+1].get_timestamp_in_seconds() - relevant_messages[i].get_timestamp_in_seconds())
        inter_message_time = round(sum(differences) / len(differences), 6)
        self.logger.debug(f"Inter message time determined for offset attack: {inter_message_time}")

        # Find messages for attack
        template_messages: List[Message] = copy.deepcopy(list(filter(lambda m: self.start_timestamp < m.get_timestamp_in_seconds() and m.get_timestamp_in_seconds() < self.end_timestamp, relevant_messages)))
        
        # shift template messages data values to the desired offset
        for message in template_messages:
            message.is_malicious = True
            # get signal value, then modify it according to the attack
            signal = int.from_bytes(message.data[self.start_bit:self.end_bit], 'big')
            if signal * 1.2 < (2 ** (8 * (self.end_bit - self.start_bit)) - 1):
                signal *= 1.2
                message.data[self.start_bit:self.end_bit] = list(int(signal).to_bytes(self.end_bit - self.start_bit, 'big'))

        # multiply malicious messages to increase their number to the proper amount due to transmission frequency difference
        for _ in range(0, int(inter_message_time / self.attack_inter_message_time)):
            self.messages_to_inject += copy.deepcopy(template_messages)
            # shift template messages according to the attack inter message time
            for message in template_messages:
                message.set_timestamp_from_seconds(message.get_timestamp_in_seconds() + self.attack_inter_message_time)
        self.messages_to_inject.sort(key=lambda x: x.timestamp)


    def generate_messages_to_inject_NEG_OFFSET(self):
        
        self.logger.debug(f"Generating attack trace with NEG-OFFSET message injection attack. From: {self.start_offset} until: {self.end_offset}")

        malicious_trace:Trace = copy.deepcopy(self.trace)

        # Calculate intermessage time
        relevant_messages:List[Message] = list(filter(lambda m: m.id == self.attack_target_id, malicious_trace.messages))
        differences = []
        for i in range(0, len(relevant_messages) - 1):
            differences.append(relevant_messages[i+1].get_timestamp_in_seconds() - relevant_messages[i].get_timestamp_in_seconds())
        inter_message_time = round(sum(differences) / len(differences), 6)
        self.logger.debug(f"Inter message time determined for offset attack: {inter_message_time}")

        # Find messages for attack
        template_messages: List[Message] = copy.deepcopy(list(filter(lambda m: self.start_timestamp < m.get_timestamp_in_seconds() and m.get_timestamp_in_seconds() < self.end_timestamp, relevant_messages)))
        
        # shift template messages data values to the desired offset
        for message in template_messages:
            message.is_malicious = True
            # get signal value, then modify it according to the attack
            signal = int.from_bytes(message.data[self.start_bit:self.end_bit], 'big')
            signal *= 0.8
            message.data[self.start_bit:self.end_bit] = list(int(signal).to_bytes(self.end_bit - self.start_bit, 'big'))

        # multiply malicious messages to increase their number to the proper amount due to transmission frequency difference
        for _ in range(0, int(inter_message_time / self.attack_inter_message_time)):
            self.messages_to_inject += copy.deepcopy(template_messages)
            # shift template messages according to the attack inter message time
            for message in template_messages:
                message.set_timestamp_from_seconds(message.get_timestamp_in_seconds() + self.attack_inter_message_time)
        self.messages_to_inject.sort(key=lambda x: x.timestamp)


    def generate_messages_to_inject_REPLAY(self):

        self.logger.debug(f"Generating attack trace with REPLAY message injection attack. From: {self.start_offset} until: {self.end_offset}")

        malicious_trace:Trace = copy.deepcopy(self.trace)

        # Calculate communication parameters
        if self.start_offset - (self.end_offset - self.start_offset) < 0:
            raise Exception(f"Attack not possible. Attack length is more than time before the attack start: {self.start_offset - (self.end_offset - self.start_offset)}")
        record_start_timestamp = malicious_trace.get_trace_length() * (self.start_offset - (self.end_offset - self.start_offset))


        # Calculate intermessage time
        relevant_messages:List[Message] = list(filter(lambda m: m.id == self.attack_target_id, malicious_trace.messages))
        differences = []
        for i in range(0, len(relevant_messages) - 1):
            differences.append(relevant_messages[i+1].get_timestamp_in_seconds() - relevant_messages[i].get_timestamp_in_seconds())
        inter_message_time = round(sum(differences) / len(differences), 6)
        self.logger.debug(f"Inter message time determined for replay attack: {inter_message_time}")

        # Phase one: record messages
        template_messages: List[Message] = copy.deepcopy(list(filter(lambda m: record_start_timestamp < m.get_timestamp_in_seconds() and m.get_timestamp_in_seconds() < self.start_timestamp, relevant_messages)))
        
        # shift template messages to the attack time interval
        for message in template_messages:
            message.set_timestamp_from_seconds(message.get_timestamp_in_seconds() + (self.start_timestamp - record_start_timestamp))
            message.is_malicious = True

        # multiply malicious messages to increase their number to the proper amount due to transmission frequency difference
        for _ in range(0, int(inter_message_time / self.attack_inter_message_time)):
            self.messages_to_inject += copy.deepcopy(template_messages)
            # shift template messages according to the attack inter message time
            for message in template_messages:
                message.set_timestamp_from_seconds(message.get_timestamp_in_seconds() + self.attack_inter_message_time)
        self.messages_to_inject.sort(key=lambda x: x.timestamp)


    def perform_attack(self):

        if len(self.messages_to_inject) == 0:
            raise Exception("Missing messages to inject")

        simulator = self.config.get('IP_addresses', 'simulator')
        attacker = self.config.get('IP_addresses', 'attacker')
        observer = self.config.get('IP_addresses', 'observer')

        if self.config.getboolean('Simulation', 'force_interface_reinitialization'):
            for device in [attacker, observer, simulator]: 
                #self.logger.debug(f"Initializing device at: {device[3:]}")
                
                device_process = subprocess.run(['ssh', device, self.config.get('Simulation', 'stop_CAN_interface')], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                #self.logger.debug(f"Result of stop interface from @ {device[3:]}: {device_process.stdout}")
                
                time.sleep(1)    
                
                device_process = subprocess.run(['ssh', device, self.config.get('Simulation', 'start_CAN_interface')], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                #self.logger.debug(f"Result of stop interface from @ {device[3:]}:{device_process.stdout}")
                self.logger.debug(f"CAN interface restarted @ {device[3:]}")

        ##############################
        # Copy files to devices
        ##############################
        #copy original trace to attacker device
        self.logger.debug(f"Rsyncing file from: {self.attack['benign_file_full_path']} to: {simulator + ':~/can-deploy/traces/' + self.attack['benign_file']}")
        simulator_copy_process = subprocess.run(['rsync', self.attack['benign_file_full_path'], simulator + ':~/can-deploy/traces/' + self.attack['benign_file']], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        #self.logger.debug(f"Copy process output: {simulator_copy_process}")

        #copy attack trace to attacker device
        self.logger.debug(f"Copying file from: {self.injected_message_filename} to: {attacker + ':~/temp-attack.log'}")
        attack_copy_process = subprocess.run(['scp', self.injected_message_filename, attacker + ':~/temp-attack.log'], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        #self.logger.debug(f"Copy process output: {attack_copy_process}")


        ##############################
        # OBSERVER  - nonblocking call
        ##############################
        self.logger.debug(f"Starting the observer.")
        observer_process = subprocess.Popen(['ssh', observer, 'cd dumps; candump -td -c -d -l -T 3000 can0'], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in observer_process.stdout:
            # seach for filename of the capture
            if 'candump' in line:
                self.trace_name = line.split("'")[1]
                self.logger.debug(f"Filename for observer received: {self.trace_name}")
                break


        ##############################
        # SIMULATOR - nonblocking call
        ##############################
        self.logger.debug(f"Starting the simulator.")
        simulator_process = subprocess.Popen(['ssh', simulator, 'cd can-deploy/traces/; canplayer -I ' + self.attack['benign_file']], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


        ##############################
        # ATTACKER - BLOCKING call
        ##############################
        self.logger.debug(f"Waiting {self.start_timestamp - 0.7}s before attack starts.")
        time.sleep(self.start_timestamp - 0.7)  # compensated for network delay

        self.logger.debug(f"Starting the attack.")
        attack_process = subprocess.run(['ssh', attacker, 'canplayer -I temp-attack.log'], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.logger.debug(f"Attack finished with code: {attack_process.returncode}")
        #self.logger.debug(f"Attack process output: {attack_process.stdout}")


        ##############################
        # Finish, join - BLOCKING calls
        ##############################
        self.logger.debug("Waiting for simulator and observer processes to end.")
        start_time = time.time()

        while simulator_process.poll() is None:
            #print("CANplayer still running")
            time.sleep(1)
            current_time = time.time()
            if (current_time - start_time) > 2 * self.trace.last_time:
                raise Exception("Simulator timeout. Aborting waiting!")
        self.logger.debug(f"Simulator exited: {simulator_process.poll()}")
        #self.logger.debug(f"Simulator process output: {simulator_process.stdout}")

        while observer_process.poll() is None:
            time.sleep(0.5)
            current_time = time.time()
            if (current_time - start_time) > 2 * self.trace.last_time:
                raise Exception("Observer timeout. Aborting waiting!")
            else:
                self.logger.debug("Observer still running")

        self.logger.debug(f"Observer exited: {observer_process.poll()}")
        #self.logger.debug(f"Observer process output: {observer_process.stdout}")


        ##############################
        # Download trace file from observer
        ##############################
        self.logger.debug(f"Copying file from: {observer + ':~/dumps/' + self.trace_name} to: {self.filename_log}")
        copy_process = subprocess.run(['scp', observer + ':~/dumps/' + self.trace_name, self.filename_log], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.logger.debug(f"Removing file at: {observer + ':~/dumps/' + self.trace_name}")
        subprocess.run(['ssh', observer, 'rm ~/dumps/' + self.trace_name], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        #self.logger.debug(f"Copy process output: {copy_process}")
