import os
bind='0.0.0.0:'+os.environ.get('PORT','8000')
workers=1
worker_class='gthread'
threads=4
timeout=60
graceful_timeout=30
keepalive=5
max_requests=1000
max_requests_jitter=100
limit_request_line=4094
limit_request_fields=50
limit_request_field_size=4096
accesslog=None
errorlog='-'
capture_output=False
# Run schema-only initialization at runtime, after the persistent disk is mounted.
def post_worker_init(worker):
 import server
 server.migrate()
 if os.environ.get('RENDER') and not server.SECURE:
  raise RuntimeError('Render deployment requires MADAR_SECURE_COOKIE=1')
