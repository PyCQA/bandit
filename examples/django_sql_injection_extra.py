from django.contrib.auth.models import User

User.objects.filter(username='admin').extra(
    select={'test': 'secure'},
    where=['secure'],
    tables=['secure']
)
User.objects.filter(username='admin').extra({'test': 'secure'})
User.objects.filter(username='admin').extra(select={'test': 'secure'})
User.objects.filter(username='admin').extra(where=['secure'])

User.objects.filter(username='admin').extra(dict(could_be='insecure'))
User.objects.filter(username='admin').extra(select=dict(could_be='insecure'))
query = '"username") AS "username", * FROM "auth_user" WHERE 1=1 OR "username"=? --'
User.objects.filter(username='admin').extra(select={'test': query})
User.objects.filter(username='admin').extra(select={'test': '%secure' % 'nos'})
User.objects.filter(username='admin').extra(select={'test': '{}secure'.format('nos')})

where_var = ['1=1) OR 1=1 AND (1=1']
User.objects.filter(username='admin').extra(where=where_var)
where_str = '1=1) OR 1=1 AND (1=1'
User.objects.filter(username='admin').extra(where=[where_str])
User.objects.filter(username='admin').extra(where=['%secure' % 'nos'])
User.objects.filter(username='admin').extra(where=['{}secure'.format('no')])

tables_var = ['django_content_type" WHERE "auth_user"."username"="admin']
User.objects.all().extra(tables=tables_var).distinct()
tables_str = 'django_content_type" WHERE "auth_user"."username"="admin'
User.objects.all().extra(tables=[tables_str]).distinct()
