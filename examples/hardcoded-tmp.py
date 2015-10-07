f = open('/tmp/abc', 'w')
f.write('def')
f.close()

# ok
f = open('/abc/tmp', 'w')
f.write('def')
f.close()

f = open('/var/tmp/123', 'w')
f.write('def')
f.close()

f = open('/dev/shm/unit/test', 'w')
f.write('def')
f.close()

# Negative test
f = open('/foo/bar', 'w')
f.write('def')
f.close()
