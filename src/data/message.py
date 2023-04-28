import logging
import textwrap
from typing import List


class Message:
    """
    A python class to define CAN messages
    """
    
    speed_id = int('0x410', 16)
    revolution_id = int('0x110', 16)
    CAN_bus_speed = 500000  # assuming a 500 kbps CAN bus
    timestamp_constant = 1000000


    def __init__(self,
                 msg_id: int,
                 data: List[int],
                 timestamp: float,
                 dlc: int = None,
                 is_error_frame: bool = False,
                 is_remote_frame: bool = False,
                 is_extended_id: bool = False):

        self.logger = logging.getLogger()
        # self.logger.debug("Creating message from id, data, timestamp.")

        # if timestamp is already normalized
        if timestamp > 10000000000:
            self.timestamp = timestamp
        else:
            self.timestamp = int(timestamp * Message.timestamp_constant)

        self.id = msg_id
        self.id_str = '{:04x}'.format(msg_id)
        self.data = data

        if dlc is not None:
            if dlc != len(data):
                print(f"Problem with message length! Expected message length: \t {len(data)} \t but found message length: \t {dlc}")
            self.dlc = dlc
        else:
            self.dlc = len(data)  # number of bytes (each represented with two characters)

        self.is_error_frame = is_error_frame
        self.is_extended_id = is_extended_id
        self.is_remote_frame = is_remote_frame

        self.is_malicious = False
        self.is_shifted_in_time = False

    def consolidate_timestamp(self, number_of_droppable_places):
        self.timestamp = int(self.timestamp / (10 ** number_of_droppable_places))

    def get_formatted_data(self) -> str:
        string_data = ""

        first = True
        for hex_num in self.data:
            if first:
                first = False
                string_data += '{:02x}'.format(hex_num)
            else:
                string_data += " " + '{:02x}'.format(hex_num)

        if len(string_data) < 23:
            string_data += " " * (23-len(string_data))

        return string_data

    def get_linux_based_formatted_data(self) -> str:
        string_data = ""

        for hex_num in self.data:
            string_data += '{:02x}'.format(hex_num)

        if len(string_data) < 17:
            string_data += " " * (17-len(string_data))

        return string_data

    def get_str_data(self) -> str:
        return "".join(['{:02x}'.format(x) for x in self.data])

    def get_message_duration_in_seconds(self) -> float:
        # 44 the message + 3 intermission period
        # 47 comes from: https://www.eecs.umich.edu/courses/eecs461/doc/CAN_notes.pdf
        return (44 + self.dlc * 8) / Message.CAN_bus_speed

    def get_header_duration_in_seconds(self) -> float:        
        return 12 * (1 / Message.CAN_bus_speed)

    def get_timestamp_in_seconds(self) -> float:
        return self.timestamp / Message.timestamp_constant

    def set_timestamp_from_seconds(self, timestamp:float):
        self.timestamp = timestamp * Message.timestamp_constant

    def get_speed_signal_value(self):
        if self.id == Message.speed_id:
            try:
                speed = int.from_bytes(self.data[1:3], 'big')
            except ValueError:
                self.logger.error("Value error during speed signal interpretation")
                return None
            return speed / 100  # speed converted to km/h
        else:
            raise Exception("Speed signal read try from NOT a speed message.")

    def __str__(self):
        return "Id: " + '{:04x}'.format(self.id) + " timestamp: " + str(self.timestamp / 1000000) + " data: " + self.get_formatted_data()

    @staticmethod
    def data_str_2_int_list(data_str: str):
        return Message.data_str_list_2_int_list(data_str.split())

    @staticmethod
    def data_str_list_2_int_list(data: List[str]):
        return [int(x, 16) for x in data]

    @staticmethod
    def data_str_processor(data_str: str):
        return Message.data_str_list_2_int_list(textwrap.wrap(data_str, 2))

    @staticmethod
    def data_formatter_verbose(in_data):
        data = ''
        for b in in_data:
            data += "{:<4} ".format(hex(b))
        # logging.debug("Formatting data verbose: " + data)
        return data

    @staticmethod
    def data_formatter(in_data):
        data = ''
        for b in in_data:
            if b == 0x0:
                data += "00"
                continue
            data_chunk = str(hex(b))
            if data_chunk.__len__() < 4:
                data_chunk = '0' + data_chunk[2:]
            else:
                data_chunk = data_chunk[2:]
            data += data_chunk
        # logging.debug("Formatting data: " + data)
        return data

    @staticmethod
    def data_reverse_formatter(in_data: str):
        counter = 0
        result = ""
        for char in in_data:
            if counter > 0 and counter % 2 == 0:
                result += " "
            result += char
            counter += 1
        return result

    @staticmethod
    def timestamp_formatter(in_data):
        # return '{:<17}'.format(in_data)
        return '{:.6f}'.format(in_data)

        # @staticmethod
        # def message_formatter_verbose(msg: can.Message):
        #     return (hex(msg.arbitration_id) + '\t'
        #             + Message.timestamp_formatter(msg.timestamp) + '\t'
        #             + Message.data_formatter_verbose(msg.data))
        #
        # @staticmethod
        # def message_formatter(msg: can.Message):
        #     return (hex(msg.arbitration_id) + '\t'
        #             + str(msg.timestamp) + '\t'
        #             + Message.data_formatter(msg.data))
