import sys
import os
import hashlib
import simplejson
import copy

from data.trace import Trace


class JSONGenerator():

    def __init__(self) -> None:
        self.json_stat = {
            "id": "S-1-1",
            "label": "benign",
            "capture": {
                "datetime": "2021-04-15",
                "details": "",
                "related_files": []
            },
            "participating_devices": [],
            "description": "",
            "capture_file": {
                "file_name": "",
                "file_size": 0,
                "file_hash": ""
            },
            "markers" : []
        }

    def generate_json(self, trace:Trace, job, attack=None):

        if attack:
            self.json_stat["id"] = attack['filename']
            self.json_stat["description"] = attack['description']
            filename = attack['filename']
        else:
            self.json_stat["id"] = job["new-name"]
            self.json_stat["description"] = job["description"]
            filename = job['benign_file']
        
        output_folder = job["output"]
                
        # capture parameters
        self.json_stat["capture"]["details"] = self.json_stat["capture"]["details"] + "Trace length: " + str(trace.get_trace_length()) + " sec."

        self.json_stat["capture"]["related_files"].append({
            "device": "Engine control ECU",
            "file_path": filename + "-speedAndRevolutionSignal.pdf",
            "description": "Plot of the engine revolution and speed signals of the vehicle."
        })


        # PARTICIPATING DEVICES
        # participating ECUs
        trace.calculate_statistics()
        ids = ""
        for id in trace.get_ids():
            ids = ids + str(id) + ", "
        self.json_stat["participating_devices"].append({
                "name": "Various ECUs sending CAN messages",
                "id": ids[:-2]
        })


        # CAPTURE FILE PARAMETERS
        # calculate hash
        with open(output_folder + filename + ".log", "rb") as f:
            bytes = f.read() # read entire file as bytes
            readable_hash = hashlib.sha256(bytes).hexdigest()
            self.json_stat["capture_file"]["file_hash"] = readable_hash

        # calculate file size
        file_size = os.stat(output_folder + filename + ".log").st_size / 1000
        self.json_stat["capture_file"]["file_size"] = int(file_size)

        # set filename
        self.json_stat["capture_file"]["file_name"] = filename + ".log"
        

        # MALICIOUS MARKERS
        if attack:
            self.json_stat["label"] = "malicious"

            # add markers for start and endpoints
            self.json_stat["markers"] = []
            self.json_stat["markers"].append({
                "packet_ID" : trace.malicious_id,
                "time" : trace.first_attack_time,
                "description" : "Start of the attack."
            })
            self.json_stat["markers"].append({
                "packet_ID" : trace.malicious_id,
                "time" : trace.last_attack_time,
                "description" : "End of the attack."
            })
        
        # save output to json file
        with open(output_folder + filename + ".json", "w") as stat_file:
            stat_file.write(simplejson.dumps(self.json_stat, indent=4))
