from logging import log
import os
import json
import copy
from multiprocessing import Pool, cpu_count

from filemanager.trace_reader import OldFormatFileReader
from filemanager.trace_reader import LinuxCompatibleFileReader
from filemanager.trace_printer import LinuxCompatibleFilePrinter
from data.trace import Trace
from infector.infection_orchestrator import InfectionOrchestrator
from infector.message_injection import MessageInjector
from doc_generator.json_generator import JSONGenerator
from doc_generator.plot_generator import Plotter
from utils.utils import Utils

 
def get_convert_jobs():
    logger.debug("Loading convert jobs...")
    job_config = json.load(open(config["Jobs"]["convert_jobs"]))
    convert_jobs = job_config["convert_jobs"]
    for job in convert_jobs:
        if "message_injection" not in job["attacks"]:
            job["attacks"]["message_injection"] = []
        if "message_modification" not in job["attacks"]:
            job["attacks"]["message_modification"] = []                    
        if "double_message_injection" not in job["attacks"]:
            job["attacks"]["double_message_injection"] = []
        if "double_message_modification" not in job["attacks"]:
            job["attacks"]["double_message_modification"] = []
    
    general_attacks = job_config["general_attacks"]
    for job in convert_jobs:
        job["attacks"]["message_injection"] += copy.deepcopy(general_attacks["message_injection"])
        job["attacks"]["message_modification"] += copy.deepcopy(general_attacks["message_modification"])
        job["attacks"]["double_message_injection"] += copy.deepcopy(general_attacks["double_message_injection"])
        job["attacks"]["double_message_modification"] += copy.deepcopy(general_attacks["double_message_modification"])

    # generate unique filenames and descriptions for each attack
    for job in convert_jobs:
        job['benign_file'] = job["new-name"] + "-benign"
        job["output"] = output_folder + job["new-name"] + "/"

        for attack in job["attacks"]["message_injection"]:
            attack['output'] = job["output"]
            attack['benign_file_full_path'] = job['output'] + job['benign_file'] + ".log"
            attack['benign_file'] = job['benign_file'] + ".log"
            attack['filename'] = f"{job['new-name']}-malicious-{attack['type']}-msg-inj-{attack['id']}-{attack['start']}-{attack['end']}"
            attack['filename_log'] = job["output"] + attack['filename'] + ".log"
            attack['filename_json'] = job["output"] + attack['filename'] + ".json"
            attack['description'] = f"{job['description']} Trace is modified with a message injection attack. Starting at {int(attack['start'] * 100)}% of the trace and ending at {int(attack['end'] * 100)}% of the trace."

        for attack in job["attacks"]["message_modification"]:
            attack['output'] = job["output"]
            attack['benign_file_full_path'] = job['output'] + job['benign_file'] + ".log"
            attack['benign_file'] = job['benign_file'] + ".log"         
            attack['filename'] = f"{job['new-name']}-malicious-{attack['type']}-msg-mod-{attack['id']}-{attack['start']}-{attack['end']}"
            attack['filename_log'] = job["output"] + attack['filename'] + ".log"
            attack['filename_json'] = job["output"] + attack['filename'] + ".json"
            attack['description'] = f"{job['description']} Trace is modified with a message modification attack. Starting at {int(attack['start'] * 100)}% of the trace and ending at {int(attack['end'] * 100)}% of the trace."

        for attack in job["attacks"]["double_message_injection"]:
            attack['output'] = job["output"]
            attack['benign_file_full_path'] = job['output'] + job['benign_file'] + ".log"
            attack['benign_file'] = job['benign_file'] + ".log"          
            attack['filename'] = f"{job['new-name']}-malicious-DOUBLE-msg-inj"
            for signal_attack in attack["targets"]:
                attack['filename'] += f"-{signal_attack['id']}-{signal_attack['type']}-{signal_attack['start']}-{signal_attack['end']}"
            attack['filename_log'] = job["output"] + attack['filename'] + ".log"
            attack['filename_json'] = job["output"] + attack['filename'] + ".json"
            # copy attack info to each signal attacks
            for signal_attack in attack["targets"]:
                signal_attack['filename'] = attack['filename']
                signal_attack['filename_log'] = attack['filename_log']
                signal_attack['output'] = attack['output']
                signal_attack['benign_file_full_path'] = attack['benign_file_full_path']
                signal_attack['benign_file'] = attack['benign_file']
            attack['description'] = f"{job['description']} Trace is modified with two message injection attack simultaneously. Starting at {int(attack['targets'][0]['start'] * 100)}% of the trace and ending at {int(attack['targets'][0]['end'] * 100)}% of the trace."

        for attack in job["attacks"]["double_message_modification"]:
            attack['output'] = job["output"]
            attack['benign_file_full_path'] = job['output'] + job['benign_file'] + ".log"
            attack['benign_file'] = job['benign_file'] + ".log"          
            attack['filename'] = f"{job['new-name']}-malicious-DOUBLE-msg-mod"
            for signal_attack in attack["targets"]:
                attack['filename'] += f"-{signal_attack['id']}-{signal_attack['type']}-{signal_attack['start']}-{signal_attack['end']}"
            attack['filename_log'] = job["output"] + attack['filename'] + ".log"
            attack['filename_json'] = job["output"] + attack['filename'] + ".json"
            attack['description'] = f"{job['description']} Trace is modified with two message modification attack simultaneously. Starting at {int(attack['targets'][0]['start'] * 100)}% of the trace and ending at {int(attack['targets'][0]['end'] * 100)}% of the trace."

    return convert_jobs


def document_jobs(jobs):
    with open(output_folder + "jobs.json", 'w') as f:
        json.dump(jobs, f, indent=4)


def prepare_job_execution(job, config):
    if config.getboolean("Dataset_generation", "force_regenerate"):
        Utils.clear_out_folder(job["output"])
    
    # Generating output folder for the new files
    if not os.path.exists(job["output"]):
        os.mkdir(job["output"])


def document_original_trace(config, job, trace):
    filename = job['benign_file']
    if config.getboolean("Dataset_generation", "force_regenerate") is False and os.path.exists(job["output"] + filename + ".log"): 
        logger.debug(f"Skipping benign file print because file already exists: {job['output'] + filename + '.log'}")        
    else:
        logger.debug(f"Processing benign file: {job['output'] + filename + '.log'}")        
        LinuxCompatibleFilePrinter(job["output"] + filename + ".log").write_messages_list(trace.messages)
        Plotter().plot_both_signals(trace, job["output"] + filename + "-speedAndRevolutionSignal")
        JSONGenerator().generate_json(trace, job)


def process_job(job, config):
    logger.info(f"Processing trace: {job['original-name']} ({job['new-name']})")
    
    # trace processing
    trace: Trace = OldFormatFileReader(input_folder + job["original-name"] + ".csv").read_complete_file()
    document_original_trace(config, job, trace)

    logger.debug("Starting infection sequence...")
    for attack in job["attacks"]["message_injection"]:
        InfectionOrchestrator().message_injection(trace, job, attack)

    for attack in job["attacks"]["message_modification"]:
        InfectionOrchestrator().message_modification(trace, job, attack)

    for attack in job["attacks"]["double_message_modification"]:
        InfectionOrchestrator().double_message_modification(trace, job, attack)

    for attack in job["attacks"]["double_message_injection"]:
        InfectionOrchestrator().double_message_injection(trace, job, attack)


if __name__ == "__main__":
    config = Utils.get_config("dataset_generator")
    logger = Utils.get_logger()
    logger.info("Dataset generator started & config loaded!")

    input_folder = config["Input"]["folder"]
    output_folder = config["Output"]["folder"]
    logger.debug(f"Input folder set: {input_folder} && Output folder set: {output_folder}")

    convert_jobs = get_convert_jobs()
    document_jobs(convert_jobs)
    for job in convert_jobs:
        prepare_job_execution(job, config)

    modification_jobs = copy.deepcopy(convert_jobs)
    modification_jobs[0]["attacks"]['message_injection'] = []  # remove injection jobs
    modification_jobs[0]["attacks"]['double_message_injection'] = []  # remove injection jobs

    injection_jobs = copy.deepcopy(convert_jobs)
    injection_jobs[0]["attacks"]['message_modification'] = []  # remove modification jobs
    injection_jobs[0]["attacks"]['double_message_modification'] = []  # remove modification jobs

    # Injection attacks
    if config.getboolean("Dataset_generation", "execute_message_injections"):
        logger.info("Running message injection attacks in single process mode")
        for job in injection_jobs:
            process_job(job, config)

    # Modification attacks
    if config.getboolean("Dataset_generation", "execute_message_modifications"):
        logger.info("Running message modification attacks in single process mode")
        for job in modification_jobs:
            process_job(job, config)

    logger.info(f"Data generation completed.")
