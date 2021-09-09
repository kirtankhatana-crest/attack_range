import json
import ssl
import requests


class CollectTestFiles:
    # Added below line to resolve SSL exceptions
    ssl._create_default_https_context = ssl._create_unverified_context

    def __init__(self):
        self.test_detection_dir = "tests"
        self.git_api_endpoint = f"https://api.github.com/repos/splunk/security_content/git/trees/develop"
        self.security_content_test_files = ""

    @staticmethod
    def fetch_file_info(endpoint, is_recursive=False):
        """
            fetch file info using API call
        """
        headers = {
            "accept": "application/vnd.github.v3+json"
        }
        params = {"recursive": 1} if is_recursive else {}
        response = requests.get(f"{endpoint}", headers=headers, params=params)
        if response.status_code == 200:
            return json.loads(response.content)
        raise Exception(f"Error occur while fetching data from github, {json.loads(response.content)}")

    def collect_all_files(self, detection_types: list):
        """
            Collect test files from the github repository
        """

        test_files_list = []

        # Fetch first set of folder structure
        fetch_first_set_from_repo = self.fetch_file_info(self.git_api_endpoint)

        # Traverse through all files and dir in main tree from first set
        for path in fetch_first_set_from_repo.get("tree"):
            print(path)
            # Fetch the tests dir
            if path.get("path") == self.test_detection_dir:
                print(path.get("path"))
                tests_dir_response = self.fetch_file_info(path.get("url"))
                # Traverse through all files and dir in tests dir
                for sub_dir in tests_dir_response.get("tree"):

                    # Check sub dir name in our detection sub dir list
                    if sub_dir.get("path") in detection_types:
                        # Fetch all the test detections in sub dir
                        fetch_detection_in_sub_dir = self.fetch_file_info(sub_dir.get("url"))
                        test_files = fetch_detection_in_sub_dir.get("tree")

                        test_files_list = [
                            f"../security_content/{self.test_detection_dir}/{sub_dir.get('path')}/{file_data.get('path')}"
                            for file_data in test_files if file_data.get("path").endswith("test.yml")]

        self.security_content_test_files = ",".join(test_files_list)
        print(self.security_content_test_files)
        return self.security_content_test_files
