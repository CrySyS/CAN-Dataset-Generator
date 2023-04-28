import configparser

from typing import List

from utils.utils import Utils
from data.message import Message


class Flow:
    def __init__(self, message: Message = None, msg_id: str = None):
        self.logger = Utils.get_logger()
        self.config = configparser.ConfigParser()
        self.config.read('config.ini')

        if message is not None:
            self.messages = [message]
            self.compressed_flow = {}

            if self.messages.__len__() == 0:
                raise Exception("Flow creation failed, because there is no message provided!")

            self.msg_id: int = message.id
            self.msg_id_str: str = message.id_str
            self.arbitration_id: int = message.id
            self.period: int = None
            self.start_time: int = -1
            self.logger.debug("Flow created for id: " + str(self.msg_id))
        elif msg_id is not None:
            self.msg_id: int = msg_id
            self.msg_id_str: str = '{:04x}'.format(msg_id)
            self.arbitration_id = int(msg_id, 16)
            self.start_time: int = -1
            self.period: int = -1
            self.messages: List[Message] = []

    def add_message(self, message: Message):
        self.messages.append(message)

    def add_message_from_parts(self, data: str, period_counter: int, difference: int):
        timestamp = self.start_time + self.period * period_counter + difference
        self.messages.append(Message(self.msg_id, Message.data_str_2_int_list(data), timestamp))
        self.start_time = timestamp

    def consolidate_timestamp(self, number_of_droppable_places):
        for msg in self.messages:
            msg.consolidate_timestamp(number_of_droppable_places)

    def get_start_time(self):
        self.logger.debug("Calculating start time for flow: " + str(self.msg_id))

        for msg in self.messages:
            if self.start_time == -1:
                self.start_time = msg.timestamp
            elif msg.timestamp < self.start_time:
                self.start_time = msg.timestamp

        if self.start_time == -1:
            raise Exception("Smallest timestamp calculation failed! Id: " + str(self.msg_id))

        self.logger.debug("Returning smallest timestamp: " + str(self.start_time))
        return self.start_time

    def compress_flow(self):

        self.compressed_flow = {}

        for msg in self.messages:
            if msg.get_str_data() in self.compressed_flow:
                self.compressed_flow[msg.get_str_data()].append(msg.timestamp)
            else:
                self.compressed_flow[msg.get_str_data()] = [msg.timestamp]

        self.logger.debug("Compressing flow data for flow: " + str(self.msg_id))

        start_timestamp = self.get_start_time()
        last_cycle = start_timestamp

        for data, timestamp_array in self.compressed_flow.items():

            # always start from the start time of the flow or not
            # last_cycle = start_timestamp

            for current_timestamp in timestamp_array:

                cycles = int((current_timestamp - last_cycle) / self.period)
                difference_minus = current_timestamp - (last_cycle + cycles * self.period)
                difference_plus = current_timestamp - (last_cycle + (cycles + 1) * self.period)

                if abs(difference_minus) < abs(difference_plus):
                    difference = difference_minus
                else:
                    difference = difference_plus
                    cycles += 1

                # next cycle should start from the last transmission time
                last_cycle = current_timestamp
                yield (data, cycles, difference)

    def is_periodic(self) -> bool:
        self.period = self.calculate_period()

        if self.messages.__len__() == 1:
            return False

        previous_timestamp = 0
        ratio = 0
        ratio_counter = 0
        non_periodic_counter = 0
        for msg in self.messages:
            if previous_timestamp != 0:
                if abs(abs(msg.timestamp - previous_timestamp) - self.period) > self.period * self.config['Flow_processing']['allowed_deviation']:
                    ratio += abs(abs(msg.timestamp - previous_timestamp) - self.period) / self.period
                    ratio_counter += 1
                    non_periodic_counter += 1
            previous_timestamp = msg.timestamp

        return not (non_periodic_counter > int(self.messages.__len__() * self.config['Flow_processing']['allowed_deviation']))

    def calculate_period(self) -> int:

        if self.messages.__len__() == 1:
            self.period = 0
            return self.period

        timestamp_differences_sum = 0
        counter = 0
        last_timestamp = 0

        for msg in self.messages:
            if last_timestamp != 0:
                timestamp_differences_sum += msg.timestamp - last_timestamp
                counter += 1
            last_timestamp = msg.timestamp
            # if more than 1000 messages then the first 1000 is enough for period calculation
            if counter > 1000:
                break

        self.period = int(timestamp_differences_sum / counter)

        return self.period

    def minimal_inter_message_time(self) -> int:
        minimum_timestamp_between_messages = -1
        searched_timestamp = -1

        previous_timestamp = -1
        for msg in self.messages:
            if previous_timestamp != -1:
                difference = msg.timestamp - previous_timestamp
                if difference < 0:
                    self.logger.warning("Causality problem! " + str(msg))
                if minimum_timestamp_between_messages == -1:
                    minimum_timestamp_between_messages = difference
                elif difference < minimum_timestamp_between_messages:
                    minimum_timestamp_between_messages = difference
                    searched_timestamp = msg.timestamp
            previous_timestamp = msg.timestamp

        self.logger.debug("Minimum time between messages: " + str(minimum_timestamp_between_messages) +
                          " at: " + str(searched_timestamp))

        return minimum_timestamp_between_messages


    def __str__(self):
        return "Flow: id: " + str(self.msg_id) + " start_time: " + str(self.start_time) + " period: " + str(
            self.period) + " # of messages: " + str(self.messages.__len__())
