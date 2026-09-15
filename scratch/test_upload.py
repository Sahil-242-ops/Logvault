import urllib.request
import json

test_content = (
    '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326\n'
    '192.168.1.50 - admin [10/Oct/2000:13:56:01 -0700] "POST /login HTTP/1.1" 401 512\n'
)
boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
body = (
    f'--{boundary}\r\n'
    f'Content-Disposition: form-data; name="file"; filename="test.log"\r\n'
    f'Content-Type: text/plain\r\n\r\n'
    f'{test_content}\r\n'
    f'--{boundary}--\r\n'
).encode('utf-8')

req = urllib.request.Request(
    'http://127.0.0.1:8000/api/upload',
    data=body,
    headers={'Content-Type': f'multipart/form-data; boundary={boundary}'}
)

try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        print('Upload Status:', resp.status)
        res_data = json.loads(resp.read().decode())
        print('Total lines:', res_data.get('file', {}).get('total_lines'))
        print('Processing time ms:', res_data.get('processing_time_ms'))
        print('Results count:', len(res_data.get('results', [])))
        print('Stats:', res_data.get('stats'))
except Exception as e:
    print('Upload error:', e)
