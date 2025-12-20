# Usage Examples

This guide provides practical examples for using the S3 IAM Proxy with various clients and SDKs.

## Table of Contents

1. [AWS CLI](#aws-cli)
2. [Python (boto3)](#python-boto3)
3. [Go SDK](#go-sdk)
4. [Node.js](#nodejs)
5. [rclone](#rclone)
6. [curl](#curl)
7. [Multipart Uploads](#multipart-uploads)

## AWS CLI

### Setup

```bash
# Install AWS CLI
pip install awscli

# Configure credentials
aws configure set aws_access_key_id user1-access-key
aws configure set aws_secret_access_key user1-secret-key
aws configure set default.region us-east-1
```

### List Buckets

```bash
aws s3 ls --endpoint-url http://localhost:8080
```

### List Objects

```bash
aws s3 ls s3://bucket-alpha/ --endpoint-url http://localhost:8080
```

### Upload File

```bash
# Upload single file
aws s3 cp local-file.txt s3://bucket-alpha/remote-file.txt \
  --endpoint-url http://localhost:8080

# Upload with metadata
aws s3 cp document.pdf s3://bucket-alpha/docs/document.pdf \
  --endpoint-url http://localhost:8080 \
  --metadata "author=John,version=1.0"
```

### Download File

```bash
aws s3 cp s3://bucket-alpha/file.txt local-file.txt \
  --endpoint-url http://localhost:8080
```

### Sync Directory

```bash
# Upload directory
aws s3 sync ./local-dir s3://bucket-alpha/remote-dir/ \
  --endpoint-url http://localhost:8080

# Download directory
aws s3 sync s3://bucket-alpha/remote-dir/ ./local-dir \
  --endpoint-url http://localhost:8080
```

### Delete File

```bash
aws s3 rm s3://bucket-alpha/file.txt --endpoint-url http://localhost:8080
```

### Presigned URLs

```bash
# Generate presigned URL (valid for 1 hour)
aws s3 presign s3://bucket-alpha/file.txt \
  --endpoint-url http://localhost:8080 \
  --expires-in 3600
```

## Python (boto3)

### Installation

```bash
pip install boto3
```

### Basic Operations

```python
import boto3
from botocore.client import Config

# Configure client
s3_client = boto3.client(
    's3',
    endpoint_url='http://localhost:8080',
    aws_access_key_id='user1-access-key',
    aws_secret_access_key='user1-secret-key',
    region_name='us-east-1',
    config=Config(signature_version='s3v4')
)

# List buckets
response = s3_client.list_buckets()
for bucket in response['Buckets']:
    print(f"  {bucket['Name']}")

# List objects
response = s3_client.list_objects_v2(Bucket='bucket-alpha')
for obj in response.get('Contents', []):
    print(f"  {obj['Key']} - {obj['Size']} bytes")

# Upload file
with open('local-file.txt', 'rb') as file:
    s3_client.put_object(
        Bucket='bucket-alpha',
        Key='remote-file.txt',
        Body=file
    )

# Download file
with open('downloaded-file.txt', 'wb') as file:
    s3_client.download_fileobj('bucket-alpha', 'remote-file.txt', file)

# Delete file
s3_client.delete_object(Bucket='bucket-alpha', Key='remote-file.txt')
```

### Streaming Upload

```python
# Upload large file with streaming (no memory buffering)
import os

file_path = 'large-file.bin'
file_size = os.path.getsize(file_path)

with open(file_path, 'rb') as file:
    s3_client.upload_fileobj(
        file,
        'bucket-alpha',
        'large-file.bin',
        Config=boto3.s3.transfer.TransferConfig(
            multipart_threshold=1024 * 1024 * 10,  # 10 MB
            multipart_chunksize=1024 * 1024 * 10   # 10 MB chunks
        )
    )
```

### Generate Presigned URL

```python
# Generate presigned GET URL
url = s3_client.generate_presigned_url(
    'get_object',
    Params={'Bucket': 'bucket-alpha', 'Key': 'file.txt'},
    ExpiresIn=3600  # 1 hour
)
print(f"Presigned URL: {url}")

# Generate presigned PUT URL
url = s3_client.generate_presigned_url(
    'put_object',
    Params={'Bucket': 'bucket-alpha', 'Key': 'upload.txt'},
    ExpiresIn=3600
)
print(f"Upload URL: {url}")
```

## Go SDK

### Installation

```bash
go get github.com/aws/aws-sdk-go-v2/config
go get github.com/aws/aws-sdk-go-v2/service/s3
go get github.com/aws/aws-sdk-go-v2/credentials
```

### Example Code

```go
package main

import (
    "context"
    "fmt"
    "os"

    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/credentials"
    "github.com/aws/aws-sdk-go-v2/service/s3"
)

func main() {
    ctx := context.Background()

    // Configure client
    cfg, err := config.LoadDefaultConfig(ctx,
        config.WithRegion("us-east-1"),
        config.WithCredentialsProvider(
            credentials.NewStaticCredentialsProvider(
                "user1-access-key",
                "user1-secret-key",
                "",
            ),
        ),
    )
    if err != nil {
        panic(err)
    }

    client := s3.NewFromConfig(cfg, func(o *s3.Options) {
        o.BaseEndpoint = aws.String("http://localhost:8080")
        o.UsePathStyle = true
    })

    // List buckets
    result, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
    if err != nil {
        panic(err)
    }
    for _, bucket := range result.Buckets {
        fmt.Printf("Bucket: %s\n", *bucket.Name)
    }

    // Upload file
    file, err := os.Open("local-file.txt")
    if err != nil {
        panic(err)
    }
    defer file.Close()

    _, err = client.PutObject(ctx, &s3.PutObjectInput{
        Bucket: aws.String("bucket-alpha"),
        Key:    aws.String("remote-file.txt"),
        Body:   file,
    })
    if err != nil {
        panic(err)
    }
    fmt.Println("File uploaded successfully")

    // Download file
    output, err := client.GetObject(ctx, &s3.GetObjectInput{
        Bucket: aws.String("bucket-alpha"),
        Key:    aws.String("remote-file.txt"),
    })
    if err != nil {
        panic(err)
    }
    defer output.Body.Close()

    // Save to file
    outFile, err := os.Create("downloaded-file.txt")
    if err != nil {
        panic(err)
    }
    defer outFile.Close()

    _, err = io.Copy(outFile, output.Body)
    if err != nil {
        panic(err)
    }
    fmt.Println("File downloaded successfully")
}
```

## Node.js

### Installation

```bash
npm install @aws-sdk/client-s3
```

### Example Code

```javascript
const { S3Client, ListBucketsCommand, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const fs = require('fs');

// Configure client
const s3Client = new S3Client({
    endpoint: 'http://localhost:8080',
    region: 'us-east-1',
    credentials: {
        accessKeyId: 'user1-access-key',
        secretAccessKey: 'user1-secret-key'
    },
    forcePathStyle: true
});

// List buckets
async function listBuckets() {
    const command = new ListBucketsCommand({});
    const response = await s3Client.send(command);
    console.log('Buckets:');
    response.Buckets.forEach(bucket => {
        console.log(`  ${bucket.Name}`);
    });
}

// Upload file
async function uploadFile(bucket, key, filePath) {
    const fileStream = fs.createReadStream(filePath);
    const command = new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: fileStream
    });
    await s3Client.send(command);
    console.log(`Uploaded ${filePath} to ${bucket}/${key}`);
}

// Download file
async function downloadFile(bucket, key, outputPath) {
    const command = new GetObjectCommand({
        Bucket: bucket,
        Key: key
    });
    const response = await s3Client.send(command);
    const writeStream = fs.createWriteStream(outputPath);
    response.Body.pipe(writeStream);
    console.log(`Downloaded ${bucket}/${key} to ${outputPath}`);
}

// Run examples
(async () => {
    await listBuckets();
    await uploadFile('bucket-alpha', 'test.txt', './local-file.txt');
    await downloadFile('bucket-alpha', 'test.txt', './downloaded.txt');
})();
```

## rclone

### Configuration

```bash
rclone config
# Choose: n (New remote)
# Name: s3proxy
# Storage: s3
# Provider: Other
# Access Key: user1-access-key
# Secret Key: user1-secret-key
# Region: us-east-1
# Endpoint: http://localhost:8080
# Location constraint: (leave blank)
# ACL: (leave blank)
```

Or create `~/.config/rclone/rclone.conf`:

```ini
[s3proxy]
type = s3
provider = Other
access_key_id = user1-access-key
secret_access_key = user1-secret-key
region = us-east-1
endpoint = http://localhost:8080
```

### Operations

```bash
# List buckets
rclone lsd s3proxy:

# List files
rclone ls s3proxy:bucket-alpha

# Upload file
rclone copy local-file.txt s3proxy:bucket-alpha/

# Upload directory
rclone sync ./local-dir s3proxy:bucket-alpha/remote-dir

# Download file
rclone copy s3proxy:bucket-alpha/file.txt ./

# Mount as filesystem (Linux/macOS)
rclone mount s3proxy:bucket-alpha /mnt/s3 --daemon
```

## curl

### Upload with Presigned URL

```bash
# First, generate presigned URL using AWS CLI or SDK
# Then use curl to upload

curl -X PUT \
  "http://localhost:8080/bucket-alpha/file.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=..." \
  --data-binary "@local-file.txt"
```

### Download with Presigned URL

```bash
curl -o downloaded-file.txt \
  "http://localhost:8080/bucket-alpha/file.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=..."
```

### Signed Request (Manual)

```bash
# This requires calculating SigV4 signature manually
# Use AWS CLI or SDK instead for production use

# Example: List bucket contents
curl -X GET \
  -H "Host: localhost:8080" \
  -H "X-Amz-Date: 20231220T120000Z" \
  -H "X-Amz-Content-Sha256: UNSIGNED-PAYLOAD" \
  -H "Authorization: AWS4-HMAC-SHA256 Credential=user1-access-key/20231220/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=..." \
  "http://localhost:8080/bucket-alpha/"
```

## Multipart Uploads

### Python (boto3)

```python
import boto3

s3_client = boto3.client(
    's3',
    endpoint_url='http://localhost:8080',
    aws_access_key_id='user1-access-key',
    aws_secret_access_key='user1-secret-key',
    region_name='us-east-1'
)

# Initiate multipart upload
response = s3_client.create_multipart_upload(
    Bucket='bucket-alpha',
    Key='large-file.bin'
)
upload_id = response['UploadId']

# Upload parts
parts = []
part_size = 5 * 1024 * 1024  # 5 MB

with open('large-file.bin', 'rb') as file:
    part_number = 1
    while True:
        data = file.read(part_size)
        if not data:
            break

        response = s3_client.upload_part(
            Bucket='bucket-alpha',
            Key='large-file.bin',
            PartNumber=part_number,
            UploadId=upload_id,
            Body=data
        )

        parts.append({
            'PartNumber': part_number,
            'ETag': response['ETag']
        })

        part_number += 1

# Complete multipart upload
s3_client.complete_multipart_upload(
    Bucket='bucket-alpha',
    Key='large-file.bin',
    UploadId=upload_id,
    MultipartUpload={'Parts': parts}
)

print("Multipart upload completed successfully")
```

### AWS CLI (Automatic Multipart)

```bash
# AWS CLI automatically uses multipart for files > 8MB
aws s3 cp large-file.bin s3://bucket-alpha/ \
  --endpoint-url http://localhost:8080
```

## Testing Authorization

### Allowed Bucket (Success)

```bash
# User has access to bucket-alpha
aws s3 ls s3://bucket-alpha/ --endpoint-url http://localhost:8080
# ✓ Returns list of objects
```

### Denied Bucket (Error)

```bash
# User does NOT have access to bucket-gamma
aws s3 ls s3://bucket-gamma/ --endpoint-url http://localhost:8080
# ✗ Returns AccessDenied error
```

### Wildcard Access

```yaml
# In config.yaml
users:
  - access_key: "admin-key"
    secret_key: "admin-secret"
    allowed_buckets:
      - "*"  # Can access ALL buckets
```

```bash
aws configure set aws_access_key_id admin-key
aws configure set aws_secret_access_key admin-secret

# Can access any bucket
aws s3 ls s3://any-bucket/ --endpoint-url http://localhost:8080
```

## Error Handling

### Signature Mismatch

```bash
$ aws s3 ls s3://bucket-alpha/ --endpoint-url http://localhost:8080

# Error response:
<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>SignatureDoesNotMatch</Code>
  <Message>The request signature we calculated does not match the signature you provided.</Message>
  <RequestId>1703078400123456789</RequestId>
</Error>
```

**Solution**: Check credentials, ensure clock is synchronized.

### Access Denied

```bash
# Error response:
<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>AccessDenied</Code>
  <Message>Access Denied</Message>
  <RequestId>1703078400123456790</RequestId>
</Error>
```

**Solution**: Add bucket to user's `allowed_buckets` in `config.yaml`.

## Best Practices

1. **Always use TLS in production**: Deploy behind HTTPS reverse proxy
2. **Use presigned URLs for direct uploads**: Reduces proxy load
3. **Enable streaming**: Set `UNSIGNED-PAYLOAD` for large files
4. **Monitor logs**: Check for authentication failures
5. **Rotate credentials**: Change access keys periodically
6. **Use least privilege**: Only grant access to necessary buckets

## Troubleshooting

### Enable Debug Logging

In your client code:

**Python:**
```python
import logging
boto3.set_stream_logger('boto3.resources', logging.DEBUG)
```

**AWS CLI:**
```bash
aws s3 ls --debug --endpoint-url http://localhost:8080
```

### Check Proxy Logs

```bash
# View proxy logs with debug enabled
# Edit config.yaml: logging.level = "debug"
./s3-proxy -config config.yaml
```

## Performance Tips

1. **Use multipart uploads for files > 10 MB**
2. **Enable HTTP/2 if using HTTPS**
3. **Increase connection pool size in SDK**
4. **Use streaming I/O, not in-memory buffers**
5. **Run proxy close to clients or backend for lower latency**

## Additional Resources

- [AWS CLI Documentation](https://docs.aws.amazon.com/cli/latest/reference/s3/)
- [boto3 Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [AWS SDK for Go](https://aws.github.io/aws-sdk-go-v2/docs/)
- [rclone Documentation](https://rclone.org/s3/)

