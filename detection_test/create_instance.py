import subprocess
import re
import json
import logging
import sys
import time
from pathlib import Path


class CreateInstance:

    def create_splunk_instance(self, app_list, splunk_version="8.1.2"):
        """
        Method to create Splunk instance using orca command.
        """
        logging.info("Splunk creation is about to start.")
        # orca_local_apps = "--local-apps https://repo.splunk.com/artifactory/Solutions/TA/ta-aws-kinesis-firehose/kinesis-mustang-builds/all-builds/latest/Splunk_TA_aws-kinesis-firehose-1.3.2-a0e6e5be.tar.gz,https://repo.splunk.com/artifactory/Solutions/TA/ta-office365/o365-mustang-builds/releases/Mustang-GA/splunk_ta_o365-2.0.6-0.spl,https://repo.splunk.com/artifactory/Solutions/DA/da-ess-amazonwebservices-content/latest/DA-ESS_AmazonWebServices_Content-3.26.0.tar.gz https://repo.splunk.com/artifactory/Solutions/DA/da-ess-aws/releases/1.0.x/1.0.0/Splunk_DA-ESS_AmazonWebServices-1.0.0-17.spl"
        # orca_create_string = f"source ~/.zshrc; orca create --sc S1 --splunk-version {splunk_version} --apps app-ess,escu::https://github.com/splunk/security_content/releases/download/v3.27.0/DA-ESS-ContentUpdate-v3.27.0.tar.gz,aws_ta::https://repo.splunk.com/artifactory/Solutions/TA/ta-aws/builds/6.0.0/latest/Splunk_TA_aws-6.0.0-11.spl,o365_ta::https://repo.splunk.com/artifactory/Solutions/TA/ta-office365/builds/2.0.3/latest/splunk_ta_o365-2.0.3-2.spl"
        # orca_create_string1 = "source ~/.zshrc; orca create --sc S1"
        orca_command = self.prepare_orca_command(app_list, splunk_version=splunk_version)
        retry = max_try = 3
        deployment_id = None
        while retry:
            try:
                response = subprocess.Popen(
                    orca_command,
                    shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                    executable="/bin/bash")
                output = ""
                for line in iter(response.stdout.readline, ''):
                    line = line.rstrip("\n")
                    logging.info(re.compile("[0(;?)[0-9]*m").sub('', line))
                    output += line
                    if not deployment_id:
                        deployment_id = re.search(r"([\w*\d*\-*]+) Network", line)
                while response.poll() is None:
                    time.sleep(0.5)
                if response.returncode != 0:
                    raise Exception("Error occurred while executing orca create command.")
                break
            except Exception as _error:
                retry -= 1
                if not retry:
                    raise Exception(f"Error occurred while creating splunk instance. {_error}")
                if deployment_id:
                    subprocess.call("orca destroy {}".format(deployment_id.group(1)),
                                    shell=True)
                    deployment_id = None
                logging.info(f"Retrying to create instance... Retry count {max_try - retry}")
        deployment_id = deployment_id.group(1)
        logging.info("Splunk instance is created successfully.")

        # Add data to json file
        self.add_instance_data_to_json(deployment_id)

    def prepare_orca_command(self, app_list, splunk_version):

        apps = {
            "aws_app": "https://repo.splunk.com/artifactory/Solutions/APP/app-aws/releases/"
                       "6.0.x/6.0.3/splunk_app_aws-6.0.3-1340.spl",
            "aws_ta": "https://repo.splunk.com/artifactory/Solutions/TA/ta-aws/builds/"
                      "6.0.0/latest/Splunk_TA_aws-6.0.0-11.spl",
            "aws_content": "https://repo.splunk.com/artifactory/Solutions/DA/da-ess-amazonwebservices-content/"
                           "latest/DA-ESS_AmazonWebServices_Content-3.26.0.tar.gz",
            "app_ess": "https://repo.splunk.com/artifactory/Solutions/APP/app-ess/releases/6.6.x/6.6.0/"
                       "splunk_app_es-6.6.0-19.spl",
            "escu": "https://github.com/splunk/security_content/releases/download/v3.27.0/"
                    "DA-ESS-ContentUpdate-v3.27.0.tar.gz",
            "o_365": "https://repo.splunk.com/artifactory/Solutions/TA/ta-office365/builds/2.0.3/latest/"
                     "splunk_ta_o365-2.0.3-2.spl"
        }
        # prepare app list
        app_list = [f"{key}::{value}" for key, value in apps.items() if key in app_list]
        app_string = ",".join(app_list)

        # Orca create command string
        orca_create_string = f"source ~/.zshrc; orca create --sc S1 --splunk-version {splunk_version} --apps {app_string}"
        print(orca_create_string)
        return orca_create_string

    @staticmethod
    def add_instance_data_to_json(deployment_id):
        """ Add instance data to orca-deploument.json

        :param deployment_id: deployment ID of splunk instance
        :type deployment_id: string
        """
        output, err = subprocess.Popen(
            "source ~/.zshrc; orca --printer json show containers --deployment-id {} | tee orca-deployment.json".format(
                deployment_id), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, executable="/bin/bash").communicate()
        print(json.loads(output))
