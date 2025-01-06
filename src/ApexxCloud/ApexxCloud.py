from datetime import datetime
from Crypto.Hash import HMAC, SHA256
import requests

#imported pycryptodome, requests --externally

'''
    ApexxCloud class for interacting with ApexxCloud API's.
    The class provides methods for uploading, downloading, deleting files, listing bucket contents, and generating signed URLs.
    Parameters:
    config (dict): A dictionary containing the following keys:
    secret_key (str): Your ApexxCloud secret key.
    access_key (str): Your ApexxCloud access key.
    region (str): The region in which your bucket is located.
    bucket (str): The default bucket to use for operations.
    For more information on the ApexxCloud API, see https://docs.apexxcloud.com/introduction
'''

class ApexxCloud:
    def __init__(self, config):
        if not isinstance(config, dict):
            raise TypeError("Configuration options must be a dictionary")
        self.config = config
        try:
            self.secret_key = config['secret_key']
            self.access_key = config['access_key']
            self.region = config['region']
            self.default_bucket = config['bucket']
            self.__base_url = 'https://api.apexxcloud.com'
            self.messages = {
                'key_error':'Missing required option: {}',
                'type_error':'{} must be a type of {}',
                'value_error':'{} must be provided for {}'
            }
        except KeyError as e:
            raise KeyError("Missing required configuration option: {}".format(e))

    def __generate_signature(self, method, path, timestamp=datetime.utcnow().isoformat() + 'Z'):
        string_to_sign = "{}\n{}\n{}".format(method, path, timestamp)
        hmac_obj = HMAC.new(self.secret_key.encode('utf-8'), string_to_sign.encode('utf-8'), digestmod=SHA256)
        return hmac_obj.hexdigest(), timestamp

    def __generate_headers(self, method, path):
        signature, timestamp = self.__generate_signature(method, path)
        return {
            'X-Access-Key': self.access_key,
            'X-Signature': signature,
            'X-Timestamp': timestamp,
        }

    def __make_request(self, method, path, options):
        if options is None:
            options = {}
        headers = self.__generate_headers(method, path)
        url = self.__base_url + path
        if 'headers'in options.keys():
            headers.update(options['headers'])
        try:
            response = requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                files=options
            )
            return response
        except requests.exceptions.RequestException as e:
            raise Exception("Error making request: {}".format(e))

    def upload_file(self,file,options):
        if not isinstance(options, dict):
            raise TypeError(self.messages['type_error'].format('options','dictionary'))
        if isinstance(file, str):
            try:
                file = open(file, 'rb')
            except OSError as e:
                raise Exception(f"Unable to open file: {e}")
        if 'key' not in options.keys():
            raise KeyError(self.messages['key_error'].format('key'))
        data = {
            'file': (options.get('filename', options['key']),file,options.get('content-type', 'application/octet-stream'))
        }
        query_params = {
            'bucket_name': options.get('bucket', self.default_bucket),
            'region' : options.get('region', self.region),
            'visibility': options.get('visibility', 'public'),
            'key': options['key']
        }
        query_string = '&'.join([f"{key}={value}" for key, value in query_params.items()])
        path = f"/api/v1/files/upload?{query_string}"
        return self.__make_request('PUT',path,data).json()
    
    def delete_file(self,bucket,key):
        if not key:
            raise Exception(self.messages['value_error'].format('key','delete_file'))
        query_params = {
            'bucket_name': bucket,
            'region':self.region,
            'key': key
        }
        query_string = '&'.join([f"{key}={value}" for key, value in query_params.items()])
        path = f'/api/v1/files/delete?{query_string}'
        return self.__make_request('DELETE',path,{}).json()
    
    def start_multipart_upload(self,bucket,key,options):
        if not key:
            raise Exception(self.messages['value_error'].format('key','start_multipart_upload'))
        if not isinstance(options,dict):
            raise TypeError(self.messages['type_error'].format('options','dictionary'))
        if not 'total_parts' in options.keys():
            raise KeyError(self.messages['key_error'].format('total_parts'))
        query_params = {
            'bucket_name': bucket,
            'region': options.get('region',self.region),
            'key': key,
            'mimeType': options.get('content-type', 'application/octet-stream'),
            'visibility': options.get('visibility', 'public'),
            'totalParts': str(options['total_parts'])
        }
        query_string = '&'.join([f"{key}={value}" for key, value in query_params.items()])
        path = f'/api/v1/files/multipart/start?{query_string}'
        return self.__make_request('POST',path,options).json()
    
    def upload_part(self,upload_id,part_number,file,options):
        if not upload_id:
            raise Exception(self.messages['value_error'].format('upload_id','upload_part'))
        if not part_number:
            raise Exception(self.messages['value_error'].format('part_number','upload_part'))
        if not isinstance(options,dict):
            raise TypeError(self.messages['type_error'].format('options','dictionary'))
        if not 'key' in options.keys():
            raise KeyError(self.messages['key_error'].format('key'))
        if not file:
            raise ValueError(self.messages['value_error'].format('file','upload_part'))
        if not 'total_parts' in options.keys():
            raise KeyError(self.messages['key_error'].format('total_parts'))
        data = {
            'file': (options.get('filename', options['key']),file,options.get('content-type', 'application/octet-stream'))
        }
        query_params = {
            'bucket_name': options.get('bucket',self.default_bucket),
            'region': options.get('region',self.region),
            'key': options.get('key'),
            'partNumber': options.get('part_number'),
            'totalParts': options['total_parts']
        }
        query_string = '&'.join([f"{key}={value}" for key, value in query_params.items()])
        path = f'/api/v1/files/multipart/{upload_id}?{query_string}'
        return self.__make_request('POST',path,data)
    
    def complete_multipart_upload(self,upload_id, parts, options):
        if not upload_id:
            raise Exception(self.messages['value_error'].format('upload_id','complete_multipart_upload'))
        if not isinstance(parts, list):
            raise TypeError(self.messages['type_error'].format('parts','list'))
        if not all(isinstance(part, dict) and 'ETag' in part and 'PartNumber' in part for part in parts):
            raise Exception("Each part must be a dictionary containing 'ETag' and 'PartNumber' keys.")
        if not isinstance(options, dict):
            raise TypeError(self.messages['type_error'].format('options','dictionary'))
        if 'key' not in options.keys():
            raise KeyError(self.messages['key_error'].format('key'))
        query_params = {
            'bucket_name': options.get('bucket', self.default_bucket),
            'region': options.get('region', self.region),
            'key': options.get('key')
        }
        query_string = '&'.join([f"{key}={value}" for key, value in query_params.items()])
        path = f'/api/v1/files/multipart/{upload_id}/complete?{query_string}'
        data = {
            'parts': parts
        }
        return self.__make_request('POST',path,data).json()

    def cancel_multipart_upload(self,upload_id,options):
        if not upload_id:
            raise ValueError(self.messages['value_error'].format('upload_id','cancel_multipart_upload'))
        if not isinstance(options, dict):
            raise TypeError(self.messages['type_error'].format('options','dictionary'))
        if 'key' not in options.keys():
            raise KeyError(self.messages['key_error'].format('key'))
        query_params = {
            'bucket_name': options.get('bucket', self.default_bucket),
            'region': options.get('region', self.region),
            'key': options.get('key')
        }
        query_string = '&'.join([f"{key}={value}" for key, value in query_params.items()])
        path = f'/api/v1/files/multipart/{upload_id}?{query_string}'
        return self.__make_request('DELETE',path,{}).json()
    
    def list_bucket_contents(self,bucket=None,options={}):
        if options and not isinstance(options, dict):
            raise TypeError(self.messages['type_error'].format('options','dictionary'))
        query_params = {
            'bucket_name': bucket if bucket is not None else self.default_bucket,
            'region': self.region,
            'prefix': options.get('prefix', ''),
            'page' : options.get('page', 1),
            'limit': options.get('limit', 20)
        }
        query_string = '&'.join([f"{key}={value}" for key, value in query_params.items()])
        path = f'/api/v1/files/contents?{query_string}'
        return self.__make_request('GET',path,{}).json()
    
    def generate_signed_url(self,type,options):
        valid_operations = [
            'upload',
            'delete',
            'start-multipart',
            'uploadpart',
            'completemultipart',
            'cancelmultipart',
            'download',
        ]
        if type not in valid_operations:
            raise ValueError("Invalid operation type")
        if not isinstance(options, dict):
            raise TypeError(self.messages['type_error'].format('options','dictionary'))
        query_params = {
            'bucket_name': options.get('bucket', self.default_bucket),
            'region': options.get('region', self.region),
        }
        if type == 'upload':
            if 'key' not in options.keys():
                raise KeyError(self.messages['key_error'].format('key'))
            query_params['key'] = options['key']
            query_params['visibility'] = options.get('visibility', 'public')
            path = '/api/v1/files/upload'
            method = 'PUT'
        elif type == 'delete':
            if 'key' not in options.keys():
                raise KeyError(self.messages['key_error'].format('key'))
            query_params['key'] = options['key']
            path = '/api/v1/files/delete'
            method = 'DELETE'
        elif type == 'start-multipart':
            if 'key' not in options.keys():
                raise KeyError(self.messages['key_error'].format('key'))
            if 'total_parts' not in options.keys():
                raise KeyError(self.messages['key_error'].format('total_parts'))
            query_params['key'] = options['key']
            query_params['visibility'] = options.get('visibility', 'public')
            query_params['mimeType'] = options.get('content-type', 'application/octet-stream')
            query_params['totalParts'] = options.get('total_parts')
            path = '/api/v1/files/multipart/start'
            method = 'POST'
        elif type == 'uploadpart':
            if 'key' not in options.keys():
                raise KeyError(self.messages['key_error'].format('key'))
            if 'part_number' not in options.keys():
                raise KeyError(self.messages['key_error'].format('part_number'))
            if 'upload_id' not in options.keys():
                raise KeyError(self.messages['key_error'].format('upload_id'))
            if 'total_parts' not in options.keys():
                raise KeyError(self.messages['key_error'].format('total_parts'))
            query_params['key'] = options['key']
            query_params['partNumber'] = options['part_number']
            query_params['totalParts'] = options['total_parts']
            path = f'/api/v1/files/multipart/{options['upload_id']}'
            method = 'POST'
        elif type == 'completemultipart':
            if 'key' not in options.keys():
                raise KeyError(self.messages['key_error'].format('key'))
            if 'upload_id' not in options.keys():
                raise KeyError(self.messages['key_error'].format('upload_id'))
            query_params['key'] = options['key']
            path = f'/api/v1/files/multipart/{options['upload_id']}/complete'
            method = 'POST'
        elif type == 'cancelmultipart':
            if 'key' not in options.keys():
                raise KeyError(self.messages['key_error'].format('key'))
            if 'upload_id' not in options.keys():
                raise KeyError(self.messages['key_error'].format('upload_id'))
            query_params['key'] = options['key']
            path = f'/api/v1/files/multipart/{options['upload_id']}'
            method = 'DELETE'
        elif type == 'download':
            if 'key' not in options.keys():
                raise ValueError(self.messages['key_error'].format('key'))
            query_params['key'] = options['key']
            query_params['expiresIn'] = options.get('expires-in', 3600)
            path = f'/api/v1/files/signed-url'
            query_string = '&'.join([f"{key}={value}" for key, value in query_params.items()])
            path = f'{path}?{query_string}'
            return self.__make_request(method,path,{}).json()
        else:
            raise Exception("Invalid operation type")
        
        query_string = '&'.join([f"{key}={value}" for key, value in query_params.items()])
        signaturepath = f'{path}?{query_string}'
        signature,timestamp = self.__generate_signature(method,signaturepath)
        query_params['access_key'] = self.access_key
        query_params['signature'] = signature
        query_params['timestamp'] = timestamp
        query_string = '&'.join([f"{key}={value}" for key, value in query_params.items()])
        return f'{self.__base_url}{path}?{query_string}'