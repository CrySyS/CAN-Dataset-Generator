import operator
import logging
# import pickle

from typing import Dict, List  # , Dict, Tuple
from abc import ABC, abstractmethod
from sys import stdout
from struct import *

from utils.utils import Utils
from data.flow import Flow
from data.message import Message


class BasePrinter(ABC):
    """ Abstract Base printer class for all printer classes. """

    output = None
    logger = None

    @abstractmethod
    def __init__(self):
        pass

    def write_messages_list(self, messages: List[Message]):

        self.logger.debug("Writing messages list to file!")

        messages.sort(key=lambda x: x.timestamp, reverse=False)

        for message in messages:
            self.output.write(Message.timestamp_formatter(message.timestamp / 1000000) + "        ")
            self.output.write('{:04x}'.format(message.id)+ "    ")
            self.output.write('000    ')  # print flags
            self.output.write(str(message.dlc) + "    ")
            self.output.write(message.get_formatted_data() + "\t\t")
            self.output.write(str(message.is_malicious) + "\t")
            self.output.write(str(message.is_shifted_in_time) + "\n")


class FilePrinter(BasePrinter):
    def __init__(self, output_filename):
        super().__init__()
        self.output = open(output_filename, 'w')
        self.logger = logging.getLogger()
        self.logger.debug("File opened for write: " + output_filename)


class ConsolePrinter(BasePrinter):
    def __init__(self):
        super().__init__()
        self.output = stdout
        self.logger = logging.getLogger()
        self.logger.debug("Console set as output parameter")


class LinuxCompatibleFilePrinter(FilePrinter):
    def __init__(self, output_filename):
        super().__init__(output_filename)

    def write_messages_list(self, messages: List[Message], show_metainfo = False):

        messages.sort(key=lambda x: x.timestamp, reverse=False)

        for message in messages:
            self.output.write("(" + Message.timestamp_formatter(message.timestamp / 1000000) + ") ")
            self.output.write("can0 ")
            self.output.write('{:03x}'.format(message.id) + "#" + message.get_linux_based_formatted_data())
            
            if show_metainfo:
                self.output.write(str(message.is_malicious) + "\t")
                self.output.write(str(message.is_shifted_in_time) + "\n")
            else:
                self.output.write("\n")



