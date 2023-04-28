import operator
from typing import List, Dict
from data.message import Message  # pylint: disable=import-error
from data.flow import Flow  # pylint: disable=import-error
from utils.utils import Utils  # pylint: disable=import-error


class Trace:

    def __init__(self, messages: List[Message]):
        self.logger = Utils.get_logger()
        self.messages: List[Message] = messages
        self.flows: Dict[str, Flow] = {}
        self.data_hist = {}
        self.id_hist = {}
        self.ids = []
        self.first_time = self.messages[0].timestamp        
        self.last_time = self.messages[-1].timestamp
        self.logger.debug(f"TraceManager: length of the trace is: {self.get_trace_length()}")
        self.speed_id = int('0x410', 16)
        self.revolution_id = int('0x110', 16)

        # for infected_traces
        self.is_infected = False
        self.first_attack_time = None
        self.last_attack_time = None
        self.malicious_id = None

        # perform housekeeping
        #self.calculate_statistics()
        self.normalize_timestamps()

    def _separate_messages(self):
        if self.messages is None:
            error = "Messages parameter not set in FlowSeparator"
            self.logger.error(error)
            raise Exception(error)

        for msg in self.messages:
            if str(msg.id) in self.flows:
                self.flows[str(msg.id)].add_message(msg)
            else:
                self.flows[str(msg.id)] = Flow(msg)

        for flow in self.flows.values():
            flow.calculate_period()

    def calculate_statistics(self):

        self.logger.debug("Calculating statistics!")

        counter = 0
        len_sum = 0
        time_sum = 0
        time_counter = 0

        for msg in self.messages:

            counter += 1
            len_sum += msg.dlc

            if not self.first_time:
                self.first_time = msg.timestamp

            if self.last_time:
                time_sum += msg.timestamp - self.last_time
                time_counter += 1

            self.last_time = msg.timestamp

            for data_byte in msg.data:
                if data_byte in self.data_hist:
                    self.data_hist[data_byte] += 1
                else:
                    self.data_hist[data_byte] = 1

            if msg.id in self.id_hist:
                self.id_hist[msg.id] += 1
            else:
                self.id_hist[msg.id] = 1

            self.ids.append(msg.id)

        # create unique list
        self.ids = list(set(self.ids))

    def normalize_timestamps(self):
        self.first_time = self.messages[0].timestamp
        for message in self.messages:
            message.timestamp -= self.first_time
        self.first_time = self.messages[0].timestamp        
        self.last_time = self.messages[-1].timestamp

    def get_number_of_error_frames(self):
        counter = 0
        for msg in self.messages:
            if msg.is_error_frame:
                counter += 1
        return counter

    def get_number_of_remote_frames(self):
        counter = 0
        for msg in self.messages:
            if msg.is_remote_frame:
                counter += 1
        return counter

    def get_ids(self):
        hex_ids = [str(hex(a)) for a in self.ids]
        hex_ids.sort()
        return hex_ids

    def get_number_of_ids(self):
        return len(self.ids)

    def get_trace_length(self):
        return (self.messages[-1].timestamp - self.messages[0].timestamp) / self.messages[0].timestamp_constant

    def get_speed_signal(self):
        
        speed_values = []
        time_values = []

        for i in range(0, len(self.messages)):
            message = self.messages[i]
            if message.id == self.speed_id:
                try:
                    speed = int.from_bytes(message.data[1:3], 'big')
                except ValueError:
                    self.logger.error("Value error during speed signal interpretation")
                    return None, None
                speed = speed / 100  # speed converted to km/h
                speed_values.append(speed)
                time_values.append(message.get_timestamp_in_seconds())

        return time_values, speed_values

    def get_revolution_signal(self):
        engine_revolution_values = []
        time_values = []

        for i in range(0, len(self.messages)):
            message = self.messages[i]
            if message.id == self.revolution_id:
                try:
                    engine_revolution = int.from_bytes(message.data[1:3], 'big', signed=False)
                except ValueError:
                    self.logger.error("Value error during revolution signal interpretation")
                    return None, None
                engine_revolution = engine_revolution / 4  # speed converted to km/h
                engine_revolution_values.append(engine_revolution)
                time_values.append(message.get_timestamp_in_seconds())

        return time_values, engine_revolution_values

    def detect_injection_parameters(self, attack:Dict):
        # malicious trace after injection attack determines its own attack parameters
        self.last_attack_time = attack['last_attack_time']
        self.malicious_id = hex(int(attack['id'], 16))
        inter_attack_time = attack['attack_inter_message_time']
        attacked_messages: List[Message] = list(filter(lambda m: m.id == int(attack['id'], 16), self.messages))

        for i in range(0, len(attacked_messages) - 1):
            
            # skip until rougly at the right time
            if attacked_messages[i].get_timestamp_in_seconds() < (attack['first_attack_time'] - 1):
                continue

            if attacked_messages[i + 1].get_timestamp_in_seconds() - attacked_messages[i].get_timestamp_in_seconds() < inter_attack_time * 1.2:
                self.first_attack_time = attacked_messages[i + 1].get_timestamp_in_seconds()
                self.logger.debug(f"First attack time for trace: {self.first_attack_time}")
                break

        if self.first_attack_time is None:
            self.logger.debug(f"First attack time could not be determined.")
        
        else:
            for i in range(0, len(attacked_messages) - 1):
                
                # skip until rougly at the right time
                if attacked_messages[i].get_timestamp_in_seconds() < (attack['last_attack_time'] - 0.2):
                    continue

                if attacked_messages[i + 1].get_timestamp_in_seconds() - attacked_messages[i].get_timestamp_in_seconds() > inter_attack_time * 3:
                    self.last_attack_time = attacked_messages[i].get_timestamp_in_seconds()
                    self.logger.debug(f"Last attack time for trace: {self.last_attack_time}")
                    break
            self.logger.debug(f"Attack parameters successfully determined.")


    def print_most_data_byte_statistics(self):
        max_value=0
        max_key=-1
        for key, value in self.data_hist.items():
            if value > max_value:
                max_value=value
                max_key=key
        print(f"Most frequent first data byte : {max_key}")
        print(
            f"Data first byte sorted histogram: {sorted(self.data_hist.items(), key=operator.itemgetter(1), reverse=True)}")

    def print_id_statistics(self):
        max_value=0
        max_key=""

        for key, value in self.id_hist.items():
            if value >= max_value:
                max_value=value
                max_key=max_key + str(hex(key)) + ", "

        printable_histogram=[(hex(item[0]), item[1]) for item in sorted(
            self.id_hist.items(), key=operator.itemgetter(1), reverse=True)]

        print(f"Most frequent id(s) : {max_key}")
        print(f"Id sorted histogram: {printable_histogram}")

    def print_example_data(self):
        for i in range(0, 10):
            print(self.messages[i])
