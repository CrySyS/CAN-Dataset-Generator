import os
import sys
import logging
import shutil
import configparser

from typing import List

class Utils:

    logger = None
    config = configparser.ConfigParser()
    is_config_loaded: bool = False

    @classmethod
    def get_logger(cls):
        if not cls.is_config_loaded:
            raise Exception("Error: Config not loaded. Logger initialization failed!")

        if not cls.logger: 
            # create logger with 'can_compressor_logger'
            cls.logger = logging.getLogger("Dataset-generator")
            cls.logger.setLevel(logging.DEBUG)

            # create file handler which logs even debug messages and separately info messages
            fh_debug = logging.FileHandler(cls.config['Log']['folder'] + cls.config['Log']['debug_filename'], mode='w')
            fh_debug.setLevel(logging.DEBUG)
            
            fh_info = logging.FileHandler(cls.config['Log']['folder'] + cls.config['Log']['filename'], mode='w')
            fh_info.setLevel(logging.INFO)

            # create console handler with a higher log level
            ch = logging.StreamHandler(sys.stdout)
            ch.setLevel(logging.INFO)

            # create formatter and add it to the handlers
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            fh_debug.setFormatter(formatter)
            fh_info.setFormatter(formatter)
            ch.setFormatter(formatter)

            # add the handlers to the logger
            cls.logger.addHandler(fh_debug)
            cls.logger.addHandler(fh_info)
            cls.logger.addHandler(ch)

            logging.getLogger('matplotlib.font_manager').disabled = True
        return cls.logger

    @classmethod
    def get_config(cls, name=None) -> List:
        if not cls.is_config_loaded:
            if name == "dataset_generator":
                cls.config.read('config/dataset_generator.ini')
            else:
                cls.config.read('config/config.ini')
            cls.is_config_loaded = True
        return cls.config

    @classmethod
    def clear_out_folder(cls, folder):
        logger = Utils.get_logger()

        if os.path.isdir(folder):
            logger.debug(f"Clearing output folder: {folder}")
            for the_file in os.listdir(folder):
                file_path = os.path.join(folder, the_file)
                try:
                    if os.path.isfile(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except Exception as e:
                    print(e)
        else:
            try:
                logger.warn(f"Folder not found: {folder} Could not be deleted.")
            except Exception as e:
                print("Logger failed. Here is your message:")
                print(e)

