import os
import copy
from typing import Dict
from doc_generator.json_generator import JSONGenerator
from doc_generator.plot_generator import Plotter
from filemanager.trace_printer import LinuxCompatibleFilePrinter
from filemanager.trace_reader import LinuxCompatibleFileReader
from infector.message_injection import MessageInjector
from data.trace import Trace
from infector.message_modification import MessageModificator
from utils.utils import Utils
from errors.exceptions import LengthException


class InfectionOrchestrator:

    def __init__(self) -> None:
        self.logger = Utils.get_logger()
        self.config = Utils.get_config()

    def message_injection(self, trace: Trace, job: Dict, attack: Dict):

        if not os.path.exists(attack["filename_log"]):
            self.logger.info(f"Infecting trace {job['new-name']} with message injection attack. Target: {attack['filename']}")
                        
            injector = MessageInjector(trace, attack)
            injector.generate_messages_to_inject()
            malicious_trace = None

            try: 
                injector.perform_attack()
                malicious_trace = LinuxCompatibleFileReader(attack["filename_log"]).read_complete_file()
                
                if abs(trace.last_time - malicious_trace.last_time) > trace.last_time * 0.05:  # allowed max deviation is 5%
                    raise LengthException(f"Attack generation failed! Stopping execution! Deviation is: {trace.last_time - malicious_trace.last_time} which is more than: {trace.last_time * 0.05}.")
                
                self.logger.debug(f"Attack generation succesful. Documenting trace.")
                malicious_trace.detect_injection_parameters(attack)
                LinuxCompatibleFilePrinter(attack["filename_log"]).write_messages_list(malicious_trace.messages)  # to normalize timestamps
                Plotter().plot_both_signals(malicious_trace, job["output"] + attack['filename'] + "-speedAndRevolutionSignal")
                JSONGenerator().generate_json(malicious_trace, job, attack)

            except LengthException as e:
                self.logger.error(str(e))
                if os.path.exists(attack["filename_log"]):
                    os.remove(attack["filename_log"])
                    self.logger.error(f"File deleted: {attack['filename_log']}. Next iteration will pick this case up again later.")

        else:
            self.logger.debug(f"Skipping infecting trace. File already exists: {attack['filename']}")


    def double_message_injection(self, trace:Trace, job: Dict, attack: Dict):
        if not os.path.exists(attack['filename_log']):
            self.logger.info(f"Infecting trace {job['new-name']} with double message injection attack. Creating: {attack['filename']}")
            self.logger.debug(f"Creating: {attack['filename_log']}")
            
            malicious_trace = copy.deepcopy(trace)

            try:
                first_attack = attack["targets"][0]
                second_attack = attack["targets"][1]
                self.logger.debug(f"Executing attack: {first_attack['type']}")
                injector = MessageInjector(malicious_trace, first_attack, second_attack)
                injector.generate_messages_to_inject()
                injector.perform_attack()
                malicious_trace = LinuxCompatibleFileReader(attack["filename_log"]).read_complete_file()
                
                if abs(trace.last_time - malicious_trace.last_time) > trace.last_time * 0.05:  # allowed max deviation is 5%
                    raise LengthException(f"Attack generation failed during the {first_attack['type']} and {second_attack['type']} execution! Stopping execution! Deviation is: {trace.last_time - malicious_trace.last_time} which is more than: {trace.last_time * 0.05}.")
            
                self.logger.debug(f"Attack generation succesful. Documenting trace.")
                malicious_trace.detect_injection_parameters(first_attack)
                LinuxCompatibleFilePrinter(attack["filename_log"]).write_messages_list(malicious_trace.messages)  # to normalize timestamps
                Plotter().plot_both_signals(malicious_trace, job["output"] + attack['filename'] + "-speedAndRevolutionSignal")
                JSONGenerator().generate_json(malicious_trace, job, attack)

            except Exception as e:
                self.logger.error(f"Exception: {e}")
                if os.path.exists(attack["filename_log"]):
                    os.remove(attack["filename_log"])
                    self.logger.error(f"File deleted: {attack['filename_log']}. Next iteration will pick this case up again later.")

        else:
            self.logger.debug(f"Skipping infecting trace. File already exists: {attack['filename']}")


    def message_modification(self, trace: Trace, job: Dict, attack: Dict):

        if not os.path.exists(attack['filename_log']):
            self.logger.info(f"Infecting trace {job['new-name']} with message modification attack. Creating: {attack['filename']}")
            self.logger.debug(f"Creating: {attack['filename_log']}")
                    
            malicious_trace = self._modify_trace(trace, attack)

            LinuxCompatibleFilePrinter(attack['filename_log']).write_messages_list(malicious_trace.messages, show_metainfo=True)
            Plotter().plot_both_signals(malicious_trace, job["output"] + attack['filename'] + "-speedAndRevolutionSignal")
            JSONGenerator().generate_json(malicious_trace, job, attack)
            
        else:
            self.logger.debug(f"Skipping infecting trace. File already exists: {attack['filename']}")


    def double_message_modification(self, trace: Trace, job: Dict, attack:Dict):

        if not os.path.exists(attack['filename_log']):
            self.logger.info(f"Infecting trace {job['new-name']} with double message modification attack. Creating: {attack['filename']}")
            self.logger.debug(f"Creating: {attack['filename_log']}")
            
            for signal_attack in attack["targets"]:
                trace = self._modify_trace(trace, signal_attack)

            LinuxCompatibleFilePrinter(attack['filename_log']).write_messages_list(trace.messages, show_metainfo=True)
            Plotter().plot_both_signals(trace, job["output"] + attack['filename'] + "-speedAndRevolutionSignal")
            JSONGenerator().generate_json(trace, job, attack)

        else:
            self.logger.debug(f"Skipping infecting trace. File already exists: {attack['filename']}")


    def _modify_trace(self, trace: Trace, attack):
        """
        Call the proper modificator function based on the attack specification.
        """

        modificator =  MessageModificator(trace, attack)
        
        match attack['type']:
            case "CONST":
                malicious_trace = modificator.modify_messages_CONST()
            case "REPLAY":
                malicious_trace = modificator.modify_messages_REPLAY()
            case "ADD-INCR":
                malicious_trace = modificator.modify_messages_ADD_INCR()
            case "ADD-DECR":
                malicious_trace = modificator.modify_messages_ADD_DECR()
            case "POS_OFFSET":
                malicious_trace = modificator.modify_messages_POS_OFFSET()
            case "NEG_OFFSET":
                malicious_trace = modificator.modify_messages_NEG_OFFSET()
            case _:
                raise Exception("Modification attack type not found!")

        return malicious_trace
