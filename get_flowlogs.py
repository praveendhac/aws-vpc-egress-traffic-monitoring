#!/usr/bin/env python3

import os
import sys
import time
import socket 
import json
import boto3
from botocore.exceptions import ClientError, PaginationError

MAX_LS_REQ_COUNT = 8
#http://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html
EGRESS_FILTER = ('[version, account_id, interface_id, '
    'srcaddr = 10.*.*.*, dstaddr != 10.*.*.*, srcport, dstport, '
    'protocol, packets, bytes, start, end, action, log_status]')
JSON_KEYS = ["flow_log_version", "aws_account_id", "nw_interface_id", 
    "srcaddr", "dstaddr", "srcport", "dstport", "protocol", "packets",
    "bytes", "estart_time", "eend_time", "nw_acl_action", "flowlog_status",
    "rstart_time", "rend_time", "instance_id", "instance_type", "instance_name",
    "subnet_id", "ami_id", "dst_domainname"]
streamname_evetime_dict = {}

def get_ec2instance_details(clients, src_ip):
    ec2_client = clients[1]
    try:
        ec2_details = ec2_client.describe_instances(Filters=[{'Name':'private-ip-address','Values':[src_ip,]}])
        return ec2_details
    except:
        print ("EXCEPTION: Could not call API describe_instances() with ", src_ip)
        return False

def enrich_push_logs(clients, raw_aws_egrflow):
    src_ip = "NONE"
    dst_hostname = "NX"
    start_time = "NONE"
    end_time = "NONE"
    vpc_id = "NONE"
    instance_id = "NX_INSTANCE"
    instance_type = "NX_INSTANCE"
    instance_name = "NX_INSTANCE"
    subnet_id = "NX_INSTANCE"
    ami_id = "NX_INSTANCE"
    final_flow = ""
    reservations = {}

    #get each VPC raw log entry
    flow_fields = raw_aws_egrflow.split(' ')
    src_ip = flow_fields[3]
    try:
        dst_hostname = socket.gethostbyaddr(flow_fields[4])[0]
    except:
        pass
    start_time = time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime(int(flow_fields[10])))
    end_time = time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime(int(flow_fields[11])))

    ec2_details = get_ec2instance_details(clients, src_ip)

    if ec2_details:
        if len(ec2_details['Reservations']) > 0:
            try:
                reservations = ec2_details['Reservations'][0]
                if 'Instances' in reservations:
                    vpc_id = reservations['Instances'][0]['VpcId']
                    instance_id = reservations['Instances'][0]['InstanceId']
                    instance_type = reservations['Instances'][0]['InstanceType']
                    #we can have multiple tags, say, Name, Owner etc.
                    if 'Tags' in reservations['Instances'][0]:
                        total_tags = len(reservations['Instances'][0]['Tags'])
                        for i in range(total_tags):
                            if 'Name' in reservations['Instances'][0]['Tags'][i]['Key']:
                                instance_name = reservations['Instances'][0]['Tags'][i]['Value']
                    subnet_id = reservations['Instances'][0]['SubnetId']
                    ami_id = reservations['Instances'][0]['ImageId']
            except:
                print ("EXCEPTION: issue in parsing ec2_details:", ec2_details)
                pass
    final_flow = raw_aws_egrflow + " " + start_time + " " + end_time  + \
            " " + instance_id + " " + instance_type + " " + instance_name + \
            " " + subnet_id + " " + ami_id + " " + dst_hostname
    #print (final_flow)
    print (json.dumps(dict(zip(JSON_KEYS,final_flow.split(" ")))))

#check environment
def read_environment_variables():
    is_env_ok = 1
    print ("Reading ENV variables")
    
    if os.environ.get("AWS_ACCESS_KEY_ID") is None:
        is_env_ok = 0
        print ("Configure ENV AWS_ACCESS_KEY_ID in Marathon/DCOS")

    if os.environ.get("AWS_SECRET_ACCESS_KEY") is None:
        is_env_ok = 0
        print ("Configure ENV AWS_SECRET_ACCESS_KEY in Marathon/DCOS")

    if os.environ.get("AWS_DEFAULT_REGION") is None:
        is_env_ok = 0
        print ("Configure ENV AWS_DEFAULT_REGION in Marathon/DCOS")

    if os.environ.get("AWS_VPC_ID") is None:
        is_env_ok = 0
        print ("Configure ENV AWS_VPC_ID in Marathon/DCOS")

    if os.environ.get("VPC_LOG_GROUP_NAME") is None:
        is_env_ok = 0
        print ("Configure ENV VPC_LOG_GROUP_NAME in Marathon/DCOS")

    if os.environ.get("SLEEP") is None:
        is_env_ok = 0
        print ("Configure ENV SLEEP in Marathon/DCOS")

    if os.environ.get("START_READING_LOGS_EPOCHTIME") is None:
        is_env_ok = 0
        print ("Configure ENV START_READING_LOGS_EPOCHTIME in Marathon/DCOS")

    if is_env_ok == 0:
        print ("Please set ENV variables to start the service")
        sys.exit(-1)
    else:
        print ("All ENV variables are set")

def get_logstreams(clients):
    logStreamFullList = []
    logstream_kwargs = {}
    logs_client = clients[0]

    log_grp_name = (str(os.environ.get("VPC_LOG_GROUP_NAME"))).strip()
    #descending is false by default
    logstream_kwargs["logGroupName"] = log_grp_name
    logstream_kwargs["orderBy"] = "LastEventTime" 

    try:
        print ("INFO: getting LogStreams from LogGroup:", log_grp_name)
        paginator = logs_client.get_paginator('describe_log_streams')
        ls_page_iterator = paginator.paginate(**logstream_kwargs)
        for logstream in ls_page_iterator:
            #check atleast one log group name is returned
            if len(logstream["logStreams"]) >= 1:
                logStreamFullList.extend(logstream["logStreams"])
            else:
                continue
    except PaginationError as e:
        print ("EXCEPTION: describe_log_streams Paginator:", e.kwargs['message'])
        pass
    
    return logStreamFullList

def reading_streams_firsttime(lstreams_list):
    global streamname_evetime_dict
    for lstream in lstreams_list:
        if lstream["logStreamName"] in streamname_evetime_dict:
            streamname_evetime_dict[lstream["logStreamName"]].append(lstream["lastEventTimestamp"])
        else:
            streamname_evetime_dict[lstream["logStreamName"]] = [lstream["lastEventTimestamp"]]
    print ("INFO: Total LogStreams:", len(streamname_evetime_dict.keys()))
    print ("INFO: List of LogStreams:", streamname_evetime_dict.keys())

#generator function 
def get_eve_per_logstream(clients, logStreamFullList, start_time, end_time):
    filterevents_kwargs = {}
    log_grp_name = (os.environ.get("VPC_LOG_GROUP_NAME")).strip()
    logs_client = clients[0]
    filterevents_kwargs['logGroupName'] = log_grp_name
    #hack: updating filterevents_kwargs with start, end times not working as expected 
    UPDATED_EGRESS_FILTER = EGRESS_FILTER.replace("start", "start >= " + str(start_time))
    UPDATED_EGRESS_FILTER = UPDATED_EGRESS_FILTER.replace("end", "end < " + str(end_time))
    filterevents_kwargs['filterPattern'] = UPDATED_EGRESS_FILTER 
    #default, old logs first new logs at last, descending
    for lstream in logStreamFullList:
        filterevents_kwargs['logStreamNames'] = [(str(lstream["logStreamName"])).strip()]
        print ("INFO: log stream name:", filterevents_kwargs['logStreamNames'])
        print ("INFO: log group name:", filterevents_kwargs['logGroupName'])
        print ("INFO: start_time:", start_time, "end_time:", end_time)
        #parse logs from firs call to API, we are here only once
        log_pages = logs_client.get_paginator('filter_log_events')
        log_iterator  = log_pages.paginate(**filterevents_kwargs)
        #call if there are log events key and there is atleast one event
        try:
            for logpage in log_iterator:
                print ("INFO: Total logs retrieved in this page:", len(logpage['events']))
                for event in logpage['events']:
                    yield event
        except PaginationError as e:
            print ("EXCEPTION: filter_log_events Paginator: ", e.kwargs['message'])
            pass
 
def run_as_service(clients):
    serv_count = 0
    lstreams_list= []
    start_time = 0

    if os.environ.get("START_READING_LOGS_EPOCHTIME") is not None:
        start_time = int(os.environ.get("START_READING_LOGS_EPOCHTIME"))

    #reads file data from external volume, create new file if not present
    if os.path.isfile("/flowlog/state/start_time"):
        fh = open("/flowlog/state/start_time","r")
        ts = fh.read()
        if len(ts) > 8:
            start_time = int(ts)
    else:
        #create file
        try:
            fh = open("/flowlog/state/start_time","w")
            fh.close()
        except:
            print ("EXCEPTION: directory /flowlog/state/ not present")
            #sys.exit(-1)
            pass

    if start_time == 0:
        print ("INFO: START_READING_LOGS_EPOCHTIME not set. Reading logs from beginning!")
    #get current/now time
    end_time = int(time.time())
    
    while True:
        call_count = 0
        while True:
            if call_count > (MAX_LS_REQ_COUNT-1):
                print ("ERROR: Could not get LogStreams even after %d attempts. Exiting!" % (call_count))
                sys.exit(-1)

            lstreams_list = get_logstreams(clients)

            if len(lstreams_list) < 1:
                print ("INFO: Could not get LogStreams(%d). Requesting again after 10 sec!" % (call_count+1))
                time.sleep(10)
                call_count +=1
                continue
            else:
                break
        #if serv_count == 0:
            #reading_streams_firsttime(lstreams_list)
        #else:
        print ("INFO: Total LogStreams:", len(lstreams_list))
        if serv_count > 0:
            start_time = end_time
            end_time = int(time.time())

        #generator returns
        for event in get_eve_per_logstream(clients, lstreams_list, start_time, end_time):
            enrich_push_logs(clients, event['message'])

        #used to check if we are in while loop for the first time
        serv_count += 1
        #sleep for 2 minute between filter_log_events API call
        print ("SLEEP between API calls: ", int(os.environ.get("SLEEP")))
        time.sleep(int(os.environ.get("SLEEP"))) 
    
def main():
    clients = []

    read_environment_variables()
    
    clients.append(boto3.client('logs'))
    clients.append(boto3.client('ec2'))
    #infinite loop
    run_as_service(clients)
    
if __name__ == '__main__':
    main()
