import sys
from time import sleep
import splunklib.results as results
import splunklib.client as client
import splunklib.results as results
import inspect
import requests

def test_baseline_search(splunk_host, splunk_password, search, pass_condition, baseline_name, baseline_file, earliest_time, latest_time, log, rest_port=8089):
    try:
        service = client.connect(
            host=splunk_host,
            port=rest_port,
            username='admin',
            password=splunk_password
        )
    except Exception as e:
        log.error("Unable to connect to Splunk instance: " + str(e))
        return {}

    # search and replace \\ with \\\
    # search = search.replace('\\','\\\\')

    if search.startswith('|'):
        search = search
    else:
        search = 'search ' + search

    kwargs = {"exec_mode": "blocking",
              "dispatch.earliest_time": earliest_time,
              "dispatch.latest_time": latest_time}

    splunk_search = search + ' ' + pass_condition

    try:
        job = service.jobs.create(splunk_search, **kwargs)
    except Exception as e:
        log.error("Unable to execute baseline: " + str(e))
        return {}

    log.info("Before test_result in test_baseline_search")
    try:
        test_results = dict()
        test_results['diskUsage'] = job['diskUsage']
        test_results['runDuration'] = job['runDuration']
        test_results['baseline_name'] = baseline_name
        test_results['baseline_file'] = baseline_file
        test_results['scanCount'] = job['scanCount']
        test_results["search"] = job["search"]
        test_results["resultCount"] = job['resultCount']
        test_results["messages"] = job["messages"]
        test_results["normalizedSearch"] = job["normalizedSearch"]
        test_results["remoteSearch"] = job["remoteSearch"]
        test_results["reportSearch"] = job["reportSearch"]
        test_results["pid"] = job["pid"]
        test_results["sid"] = job["sid"]
        test_results["eventAvailableCount"] = job["eventAvailableCount"]
        test_results["eventCount"] = job["eventCount"]
        test_results["eventFieldCount"] = job["eventFieldCount"]
        test_results["eventSearch"] = job["eventSearch"]
        test_results["isFailed"] = job["isFailed"]
        test_results["ttl"] = job["ttl"]

    except Exception as exc:
        log.info(f"Caught an exception during updating test_results in test_baseline_search, exception: {exc}")
    log.info(f"After test_result in test_baseline_search : {test_results}")


    if int(job['resultCount']) != 1:
        log.error("Test failed for baseline: " + baseline_name)
        test_results['error'] = True
        return test_results
    else:
        log.info("Test successful for baseline: " + baseline_name)
        test_results['error'] = False
        return test_results


def test_detection_search(splunk_host, splunk_password, search, pass_condition, detection_name, detection_file, earliest_time, latest_time, log, rest_port=8089):
    try:
        service = client.connect(
            host=splunk_host,
            port=rest_port,
            username='admin',
            password=splunk_password
        )
    except Exception as e:
        log.error("Unable to connect to Splunk instance: " + str(e))
        return {}

    # search and replace \\ with \\\
    # search = search.replace('\\','\\\\')

    if search.startswith('|'):
        search = search
    else:
        search = 'search ' + search

    kwargs = {"exec_mode": "blocking",
              "dispatch.earliest_time": earliest_time,
              "dispatch.latest_time": latest_time}

    splunk_search = search + ' ' + pass_condition

    try:
        job = service.jobs.create(splunk_search, **kwargs)
    except Exception as e:
        log.error("Unable to execute detection: " + str(e))
        return {}

    log.info("Before test_result in test_detection_search")
    try:
        test_results = dict()
        test_results['diskUsage'] = job['diskUsage']
        test_results['runDuration'] = job['runDuration']
        test_results['detection_name'] = detection_name
        test_results['detection_file'] = detection_file
        test_results['scanCount'] = job['scanCount']
        test_results["search"] = job["search"]
        test_results["resultCount"] = job['resultCount']
        test_results["messages"] = job["messages"]
        test_results["normalizedSearch"] = job["normalizedSearch"]
        test_results["remoteSearch"] = job["remoteSearch"]
        test_results["reportSearch"] = job["reportSearch"]
        test_results["pid"] = job["pid"]
        test_results["sid"] = job["sid"]
        test_results["eventAvailableCount"] = job["eventAvailableCount"]
        test_results["eventCount"] = job["eventCount"]
        test_results["eventFieldCount"] = job["eventFieldCount"]
        test_results["eventSearch"] = job["eventSearch"]
        test_results["isFailed"] = job["isFailed"]
        test_results["ttl"] = job["ttl"]

    except Exception as exc:
        log.info(f"Caught an exception during updating test_results in test_detection_search, exception: {exc}")
    log.info(f"After test_result in test_detection_search {test_results}")


    if int(job['resultCount']) != 1:
        log.error("test failed for detection: " + detection_name)
        test_results['error'] = True
        return test_results
    else:
        log.info("test successful for detection: " + detection_name)
        test_results['error'] = False
        return test_results


def search(splunk_host, splunk_password, search_name, log):
    print('\nexecute savedsearch: ' + search_name + '\n')

    service = client.connect(
        host=splunk_host,
        port=8089,
        username='admin',
        password=splunk_password
    )

    # Retrieve the new search
    mysavedsearch = service.saved_searches[search_name]

    kwargs = {"disabled": False,
              "dispatch.earliest_time": "-60m",
              "dispatch.latest_time": "now"}

    # Enable savedsearch and adapt the scheduling time
    mysavedsearch.update(**kwargs).refresh()

    # Run the saved search
    job = mysavedsearch.dispatch()

    # Create a small delay to allow time for the update between server and client
    sleep(2)

    # Wait for the job to finish--poll for completion and display stats
    while True:
        job.refresh()
        stats = {"isDone": job["isDone"],
                 "doneProgress": float(job["doneProgress"]) * 100,
                 "scanCount": int(job["scanCount"]),
                 "eventCount": int(job["eventCount"]),
                 "resultCount": int(job["resultCount"])}
        status = ("\r%(doneProgress)03.1f%%   %(scanCount)d scanned   "
                  "%(eventCount)d matched   %(resultCount)d results") % stats

        sys.stdout.write(status)
        sys.stdout.flush()
        if stats["isDone"] == "1":
            break
        sleep(2)

    # Get the results and display them
    for result in results.ResultsReader(job.results()):
        print()
        print(result)

    # disable the savedsearch
    kwargs = {"disabled": True}
    mysavedsearch.update(**kwargs).refresh()


def list_searches(splunk_host, splunk_password):
    service = client.connect(
        host=splunk_host,
        port=8089,
        username='admin',
        password=splunk_password
    )

    # List the saved searches that are available to the current user
    return service.saved_searches


def test():
    service = client.connect(
        host='52.29.172.70',
        port=8089,
        username='admin',
        password='I-l1ke-Attack-Range!'
    )

    myindex = service.indexes["test"]
    uploadme = "/opt/splunk/attack-range-windows-domain-controller_sysmon.xml"

    kwargs = {"source": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"}

    return_value = myindex.upload(uploadme)
    print(return_value)


def export_search(host, s, password, export_mode="raw", out=sys.stdout, username="admin", port=8089):
    """
    Exports events from a search using Splunk REST API to a local file.

    This is faster than performing a search/export from Splunk Python SDK.

    @param host: splunk server address
    @param s: search that matches events
    @param password: Splunk server password
    @param export_mode: default `raw`. `csv`, `xml`, or `json`
    @param out: local file pointer to write the results
    @param username: Splunk server username
    @param port: Splunk server port
    """
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    r = requests.post("https://%s:%d/servicesNS/admin/search/search/jobs/export" % (host, port),
                      auth=(username, password),
                      data={'output_mode': export_mode,
                            'search': s,
                            'max_count': 1000000},
                      verify=False)
    out.write(r.text.encode('utf-8'))



def delete_attack_data(splunk_host, splunk_password, splunk_mgmt_port=8089):
    try:
        service = client.connect(
            host=splunk_host,
            port=splunk_mgmt_port,
            username='admin',
            password=splunk_password
        )
    except Exception as e:
        print("Unable to connect to Splunk instance: " + str(e))
        return False

    splunk_search = 'search index=test* | delete'

    kwargs = {"exec_mode": "blocking",
              "dispatch.earliest_time": "-1d",
              "dispatch.latest_time": "now"}

    try:
        job = service.jobs.create(splunk_search, **kwargs)
    except Exception as e:
        print("Unable to execute search: " + str(e))
        return False

    return True


def execute_savedsearch(splunk_host, splunk_password, search_name, earliest, latest):
    try:
        service = client.connect(
            host=splunk_host,
            port=8089,
            username='admin',
            password=splunk_password,
            app="dev_sec_ops_analytics"
        )
    except Exception as e:
        print("Unable to connect to Splunk instance: " + str(e))
        return False  

    mysavedsearch = service.saved_searches[search_name]

    kwargs = {"dispatch.earliest_time": "-" + earliest,
        "dispatch.latest_time": latest,
         "disabled": 0}

    mysavedsearch.update(**kwargs).refresh()

    job = mysavedsearch.dispatch()
    sleep(2)
    while True:
        job.refresh()
        if job["isDone"] == "1":
            break
        sleep(2)

    jobresults = job.results()

    kwargs = {"disabled": 1}
    mysavedsearch.update(**kwargs).refresh()
