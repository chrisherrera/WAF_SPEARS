'''
Chris Herrera
https://github.com/chrisherrera
'''

import sys, time, random, string
try:
	import requests
	requests.packages.urllib3.disable_warnings()
except ImportError:
	print 'ERROR: You must have the "requests" module installed.'
	print '  Try the following command: pip install requests'
	sys.exit()

def main():
	sleep = [0.1,0.2,0.3,0.4,0.5]
	timeout = 5

	# triggers 950103 "Path Traversal Attack"
	path_traversal = {}
	path_traversal['name'] = 'path traversal'
	path_traversal['payload'] = '../../../../../../../../../../etc/hosts'
	path_traversal['location'] = 'cookie'

	# triggers 950001 "SQL Injection Attack"
	SQLi = {}
	SQLi['name'] = 'SQLi'
	SQLi['payload'] = '/admin.aspx?union select 0,username password'
	SQLi['location'] = 'query_string'

	# triggers 431004 "SLR: Drupal 7.x/8.x SA-CORE-2018-004"
	drupal = {}
	drupal['name'] = 'drupal'
	drupal['payload'] = '/page.node?q=node/99/delete&destination=node?q[%2523][]=passthru%26q[%2523type]=markup%26q[%2523markup]=id;uname+-a'
	drupal['location'] = 'query_string'

	# we want drupal to show up 4x as often as the other attacks
	payloads = []
	payloads.append(path_traversal)
	payloads.append(SQLi)
	payloads.append(drupal)
	payloads.append(drupal)
	payloads.append(drupal)
	payloads.append(drupal)

	#struts = '%{(#_="struts").(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context["com.opensymphony.xwork2.ActionContext.container"]).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd="dir").(#iswin=(@java.lang.System@getProperty("os.name").toLowerCase().contains("win"))).(#cmds=(#iswin?{"cmd.exe","/c",#cmd}:{"/bin/bash","-c",#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}'

	while True:
		URL = 'http://block.chrisputer.com'
		payload = random.choice(payloads)
		if payload['location'] == 'query_string':
			URL += payload['payload']
			cookies = dict()
		elif payload['location'] == 'cookie':
			cookies = dict(payload_cookie = payload['payload'])
		r = requests.get(URL, cookies = cookies, verify = False, timeout = timeout)
		print r.status_code, payload['name']
		time.sleep(random.choice(sleep))

if __name__ == '__main__':
	main()
