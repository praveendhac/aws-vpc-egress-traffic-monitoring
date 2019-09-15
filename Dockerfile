FROM python:alpine

ENV ALPINE_PACKAGES python-dev py-pip
RUN apk update && apk upgrade && apk add --no-cache $ALPINE_PACKAGES
RUN pip install --no-cache-dir boto3
RUN mkdir -p /root/.aws

ENV AWS_DEFAULT_REGION=aa-88-11-bb
ENV AWS_ACCESS_KEY_ID=aa-88-11-bb
ENV AWS_SECRET_ACCESS_KEY=aa-88-11-bb
ENV AWS_VPC_ID=aa-88-11-bb
ENV VPC_LOG_GROUP_NAME=aa-88-11-bb
ENV START_READING_LOGS_EPOCHTIME=aa-88-11-bb
ENV SLEEP=aa-88-11-bb

ADD get_flowlogs.py /

CMD [ "python3", "./get_flowlogs.py" ]
