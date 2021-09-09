import logging
import configparser
import json


class ConfigurationSet:

    def set_config_variable(self):
        """
            Set configuration parameters
        """
        # Open orca deployment file
        with open("orca-deployment.json") as f:
            try:
                orca_json = json.loads(f.read())
            except ValueError as error:
                error_message = "Error decoding orca-deployment.json file. Make sure the file has deployment details " \
                                "and in valid json format. Reason: "
                logging.error(error_message)
                raise ValueError(error_message + error) from error

        # load config file
        configuration = self.load_config_template()

        # Set 
        configuration._sections['global']['cloud_provider'] = "orca"
        configuration._sections['range_settings']['private_key_path'] = ""

        # Set orca variables
        self.set_orca_variables(configuration, orca_json)

        print(configuration._sections["orca_instance"]["splunk_instance_ip"])
        print(configuration._sections['global']['cloud_provider'])


        # Write configuration variables to conf file
        with open("../attack_range.conf", 'w') as configfile:
            configuration.write(configfile)

    def load_config_template(self):
        config_template = '../attack_range.conf.template'
        config = configparser.RawConfigParser()
        config.read(config_template)
        return config

    def set_orca_variables(self, configuration, orca_json):
        """Set orca variables

        :param configuration: [description]
        :type configuration: [type]
        :param orca_json: [description]
        :type orca_json: [type]
        """

        orca_user = list(orca_json.keys())[0]
        orca_deployment_id = list(orca_json[orca_user])[0]
        splunk_container = list(orca_json[orca_user][orca_deployment_id]['containers'].values())[0]

        configuration._sections["orca_instance"]["splunk_instance_ip"] = splunk_container['ssh_address']
        configuration._sections['global']['attack_range_password'] = splunk_container['splunk_password']
        configuration._sections["orca_instance"]["splunk_ssh_port"] = splunk_container['Ports']['2222/tcp'].split(':')[1]
        configuration._sections["orca_instance"]["splunk_rest_port"] = splunk_container['Ports']['8089/tcp'].split(':')[1]
