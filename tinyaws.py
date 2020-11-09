# Copyright is waived. No warranty is provided. Unrestricted use and modification is permitted.

import os
import sys
import re
import hmac
import json
import datetime
import xml.etree.ElementTree as ET
from hashlib import sha256
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


# Locate access credentials
class AWSCredentials:

    __instance = None

    @staticmethod
    def instance():
        if AWSCredentials.__instance is None:
            AWSCredentials.__instance = AWSCredentials()
        return AWSCredentials.__instance

    def __init__(self):
        # Parse local credentials file if it exists
        self.credentials_path = os.path.expanduser("~/.aws/credentials")
        self.profiles = {}
        self.current_profile = "default"
        access_key = secret_key = profile_name = None
        if os.path.exists(self.credentials_path):
            with open(self.credentials_path, "r") as f:
                for line in f.readlines():
                    if not profile_name:
                        match = re.search(r"\[([a-zA-Z0-9_\-.]+)", line)
                        if match:
                            profile_name = match.group(1)
                    else:
                        parts = line.split("=")
                        if parts[0].strip() == "aws_access_key_id":
                            access_key = parts[1].strip()
                        elif parts[0].strip() == "aws_secret_access_key":
                            secret_key = parts[1].strip()
                        if access_key and secret_key:
                            self.profiles[profile_name] = (access_key, secret_key)
                            access_key = secret_key = profile_name = None

    def select_profile(self, name):
        self.current_profile = name

    def get_credentials(self):
        # Attempt to get the credentials from the local credentials file
        if self.current_profile in self.profiles:
            return self.profiles[self.current_profile]

        # Attempt to get the credentials from environment variables
        access_key = os.environ["aws_access_key_id"] if "aws_access_key_id" in os.environ else None
        secret_key = os.environ["aws_secret_access_key"] if "aws_secret_access_key" in os.environ else None
        if access_key and secret_key:
            return access_key, secret_key

        # Couldn't locate any credentials; oh well...
        sys.exit("AWS Credentials not found")


# Generate API authorization token
class AWSAuthorization:

    # Generate timestamp in format needed for a V4 authorization
    @staticmethod
    def generate_v4_date():
        return datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

    # Generate a V4 token
    # See http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
    @staticmethod
    def generate_v4_authorization(access_key, secret_key, method, service, region, uri, query, date, canonical_headers, signed_headers, payload_hash):

        # Fix AWS api quirk; query must have an "=" in the canonical request
        if query and "=" not in query:
            query += "="

        # Generate the canonical request
        today = date[:8]
        canonical_request = method + "\n" + uri + "\n" + query + "\n" + canonical_headers + "\n" + signed_headers + "\n" + payload_hash
        scope = today + "/" + region + "/" + service + "/aws4_request"
        string_to_sign = "AWS4-HMAC-SHA256\n" + date + "\n" + scope + "\n" + sha256(canonical_request.encode("latin_1")).hexdigest()

        # Generate the signing key
        date_key = hmac.new(("AWS4" + secret_key).encode("latin_1"), date[:8].encode("latin_1"), sha256).digest()
        date_region_key = hmac.new(date_key, region.encode("latin_1"), sha256).digest()
        date_region_service_key = hmac.new(date_region_key, service.encode("latin_1"), sha256).digest()
        signing_key = hmac.new(date_region_service_key, b"aws4_request", sha256).digest()

        # Generate the authorization
        signature = hmac.new(signing_key, string_to_sign.encode("latin_1"), sha256).hexdigest()
        authorization = "AWS4-HMAC-SHA256 Credential=" + access_key + "/" + scope + ", SignedHeaders=" + signed_headers + ", Signature=" + signature
        return authorization


# Make an API call
class AWSRequest:

    # Make a request to a REST-style API with V4 authentication
    @staticmethod
    def send_rest_request_v4(service, method, region, endpoint, uri, query="", headers=None, payload=None, sign_payload=False):
        # Generate hash of payload if necessary
        if sign_payload:
            if payload:
                payload_hash = sha256(payload).hexdigest()
            else:
                # Hash of empty string
                payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        else:
            payload_hash = "UNSIGNED-PAYLOAD"

        # Get access credentials
        access_key, secret_key = AWSCredentials.instance().get_credentials()

        # Generate list of headers needed for signing (must be in alphabetical order)
        date = AWSAuthorization.generate_v4_date()
        signed_headers = "host;x-amz-content-sha256;x-amz-date"
        canonical_headers = "host:{0}\nx-amz-content-sha256:{1}\nx-amz-date:{2}\n".format(endpoint, payload_hash, date)

        # Sign the request
        authorization = AWSAuthorization.generate_v4_authorization(access_key, secret_key, method, service, region, uri, query, date, canonical_headers, signed_headers, payload_hash)

        # Generate HTTP headers for request
        headers = headers if headers else {}
        headers.update({
            "host": endpoint,
            "x-amz-date": date,
            "x-amz-content-sha256": payload_hash,
            "authorization": authorization
        })

        # Execute request
        if query:
            uri = "https://" + endpoint + uri + "?" + query
        else:
            uri = "https://" + endpoint + uri
        return AWSRequest._send_request(uri, method=method, data=payload, headers=headers)

    # Make a request to a Target-style API with V4 authentication
    @staticmethod
    def send_target_request(service, region, target, content_type, payload):
        # Convert payload to JSON and generate hash
        payload = json.dumps(payload).encode("latin_1")
        payload_hash = sha256(payload).hexdigest()

        # Get access credentials
        access_key, secret_key = AWSCredentials.instance().get_credentials()

        # Generate list of headers needed for signing (must be in alphabetical order)
        date = AWSAuthorization.generate_v4_date()
        endpoint = service + "." + region + ".amazonaws.com"
        signed_headers = "host;x-amz-content-sha256;x-amz-date"
        canonical_headers = "host:{0}\nx-amz-content-sha256:{1}\nx-amz-date:{2}\n".format(endpoint, payload_hash, date)
        signed_headers += ";x-amz-target"
        canonical_headers += "x-amz-target:{0}\n".format(target)

        # Sign the request
        authorization = AWSAuthorization.generate_v4_authorization(access_key, secret_key, "POST", service, region, "/", "", date, canonical_headers, signed_headers, payload_hash)

        # Generate HTTP headers for request
        headers = {
            "host": endpoint,
            "content-type": content_type,
            "x-amz-date": date,
            "x-amz-content-sha256": payload_hash,
            "x-amz-target": target,
            "authorization": authorization
        }

        # Execute request
        return AWSRequest._send_request("https://" + endpoint, method="POST", data=payload, headers=headers)

    # Make a request to an Action-style API with V4 authentication
    @staticmethod
    def send_action_request(service, region, endpoint, action):
        # Encode payload and generate hash
        payload = urlencode(action).encode("latin_1")
        payload_hash = sha256(payload).hexdigest()

        # Get access credentials
        access_key, secret_key = AWSCredentials.instance().get_credentials()

        # Generate list of headers needed for signing (must be in alphabetical order)
        date = AWSAuthorization.generate_v4_date()
        signed_headers = "host;x-amz-content-sha256;x-amz-date"
        canonical_headers = "host:{0}\nx-amz-content-sha256:{1}\nx-amz-date:{2}\n".format(endpoint, payload_hash, date)

        # Sign the request
        authorization = AWSAuthorization.generate_v4_authorization(access_key, secret_key, "POST", service, region, "/", "", date, canonical_headers, signed_headers, payload_hash)

        # Generate HTTP headers for request
        headers = {
            "host": endpoint,
            "content-type": "application/x-www-form-urlencoded",
            "x-amz-date": date,
            "x-amz-content-sha256": payload_hash,
            "authorization": authorization
        }

        # Execute request
        return AWSRequest._send_request("https://" + endpoint, data=payload, headers=headers)

    # Synchronous HTTP/S request
    @staticmethod
    def _send_request(uri, method=None, data=None, headers=None):
        request = Request(uri)
        if method:
            request.get_method = lambda: method
        if data:
            request.data = data
        if headers:
            for k, v in headers.items():
                request.add_header(k, v)
        try:
            fp = urlopen(request)
            headers = {key.lower(): fp.headers[key] for key in fp.headers}
            return fp.code, fp.read(), headers                  # On success the response body is returned as bytes()
        except HTTPError as e:
            headers = {key.lower(): e.headers[key] for key in e.headers}
            return e.code, e.read().decode("latin_1"), headers         # On fail the response body is returned as str()
        except URLError as e:
            return 0, "URL Error", []


# Parse XML response from an API call
class XMLResponse:

    @staticmethod
    def xml_to_dict(xml):
        xml = xml.decode("latin_1")
        xml = re.sub(' xmlns="[^"]+"', '', xml, count=1)
        root = ET.fromstring(xml)
        return {root.tag: XMLResponse._element_to_value(root)}

    @staticmethod
    def _element_to_value(element):
        if len(element) == 0:
            # this is a leaf node in the XML tree so just return its value
            value = element.text
        else:
            value = {}
            # The node has children, parse them recursively
            for child in element:
                k = child.tag
                v = XMLResponse._element_to_value(child)
                if k in value:
                    # This key already exists so convert it to a list, or append to the list if already converted
                    if isinstance(value[k], list):
                        value[k].append(v)
                    else:
                        value[k] = [value[k], v]
                else:
                    value[k] = v
        return value

    # Convenience method to return map element as an iterable
    @staticmethod
    def as_iterable(dictionary, key):
        if dictionary is not None and key in dictionary:
            if isinstance(dictionary[key], list):
                return dictionary[key]    # The element is already a list
            else:
                return [dictionary[key]]  # Convert element to a list
        return []


if __name__ == '__main__':
    # Example;  list all S3 buckets
    region = "us-west-2"
    endpoint = "s3.{0}.amazonaws.com".format(region)
    code, body, headers = AWSRequest.send_rest_request_v4("s3", "GET", region, endpoint, "/")
    if code == 200:
        response = XMLResponse.xml_to_dict(body)
        buckets = XMLResponse.as_iterable(response["ListAllMyBucketsResult"]["Buckets"], "Bucket")
        for bucket in buckets:
            name = bucket["Name"]
            creation_date = bucket["CreationDate"]
            print("{0} {1}".format(creation_date, name))
