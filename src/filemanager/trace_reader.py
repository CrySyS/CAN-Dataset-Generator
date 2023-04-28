# import can  # http://skpang.co.uk/blog/archives/1220

from typing import List

from data.message import Message
from data.trace import Trace
from utils.utils import Utils


# example lines
# 1483093132.049669        0380    000    8    30 bb 82 00 9d 53 00 81
# 1483093132.128087        0280    000    8    00 00 00 00 00 00 00 00
# 1483093132.130010        0180    000    6    64 a0 7f ff 44 00
# timestamp                arb_id  flag   dlc  data
# arb_id = arbitration_id
# flag = remote_frame|id_type|error_frame


class OldFormatFileReader:
    def __init__(self, file):
        self.file_name = file
        self.logger = Utils.get_logger()

    def read_line(self):
        cnt = 0
        with open(self.file_name) as f:
            for line in f:
                cnt += 1
                try:
                    if line == '\n':
                        continue

                    split_line = line.split(' ')
                    split_line = [x for x in split_line if x != '']

                    yield Message(
                        timestamp=float(split_line[0]),
                        msg_id=int(split_line[1], 16),
                        is_remote_frame=bool(int(split_line[2][0])),
                        is_extended_id=bool(int(split_line[2][1])),
                        is_error_frame=bool(int(split_line[2][2])),
                        dlc=int(split_line[3]),
                        data=Message.data_str_list_2_int_list(split_line[4:])
                    )

                except IndexError:
                    self.logger.debug(f"Error, unable to parse line #{cnt} (skipping): '{line}'")
                    continue

    def read_complete_file(self) -> Trace:

        cnt = 0
        can_messages = []

        with open(self.file_name) as f:
            for line in f:
                cnt += 1
                try:

                    if line == '\n':
                        continue

                    split_line = line.split(' ')
                    split_line = [x for x in split_line if x != '']

                    can_message = Message(
                        msg_id=int(split_line[1], 16),
                        data=Message.data_str_list_2_int_list(split_line[4:]),
                        timestamp=float(split_line[0]),
                        dlc=int(split_line[3]),
                        is_error_frame=bool(int(split_line[2][2])),
                        is_remote_frame=bool(int(split_line[2][0])),
                        is_extended_id=bool(int(split_line[2][1]))
                    )

                    can_messages.append(can_message)

                except IndexError:
                    self.logger.debug(f"Error, unable to parse line #{cnt} (skipping): '{line}'")
                    continue

        return Trace(can_messages)



class LinuxCompatibleFileReader():

    def __init__(self, input_filename):
        self.file_name = input_filename
        self.logger = Utils.get_logger()

    def read_complete_file(self) -> Trace:

        self.logger.debug(f"Reading file: {self.file_name}")

        cnt = 0
        can_messages = []

        with open(self.file_name) as f:
            for line in f:
                cnt += 1
                try:

                    if line == '\n':
                        continue

                    split_line = line.split(' ')
                    split_line = [x for x in split_line if x != '']

                    msg = split_line[2].split('#')
                    id = msg[0]
                    data = msg[1]

                    can_message = Message(
                        timestamp=float(split_line[0][1:-1]),
                        msg_id=int(id, 16),
                        data=Message.data_str_processor(data)
                    )

                    can_messages.append(can_message)

                except IndexError:
                    self.logger.debug(f"Error, unable to parse line #{cnt} (skipping): '{line}'")
                    continue

        return Trace(can_messages)
