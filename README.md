# ApexxCloud

## Description
Python package for ApexxCloud API's.

## Installation 

```bash
pip install apexxcloud
```

## Quick Start
```python
from ApexxCloud import ApexxCloud

client = ApexxCloud({
    'access_key':'your_access_key',
    'secret_key':'your_secret_key',
    'bucket': 'your_bucket',
    'region': 'your_region'
})
```
## Features

- Simple file upload
- Multipart upload for large files
- File deletion
- Signed URL generation
- Bucket contents listing

## API Reference

### File Operations

#### Upload a File
```python
result = client.upload_file(file,options)
```

#### Delete a File
```python
result = client.delete_file(bucket,key)
```

#### Get a Signed URL
```python
result = client.generate_signed_url(type,options)
```

#### Start MultiPart Upload
```python
result = client.start_multipart_upload(bucket,key,options)
```

#### Upload Parts
```python
result = client.upload_part(upload_id, partNumber, file, options)
```

#### Complete MultiPart Upload
```python
result = client.complete_multipart_upload(upload_id, parts, options)
```

#### Cancel MultiPart Upload
```python
result = client.cancel_multipart_upload(upload_id, options)
```

## Documentation

For detailed documentation, visit [docs.apexxcloud.com](https://docs.apexxcloud.com)

## License

MIT