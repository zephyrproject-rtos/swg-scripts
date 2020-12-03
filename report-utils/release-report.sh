#!/usr/bin/env bash

release_script=$ZEPHYR_BASE/../swg-scripts/scan.py
email_author="Zephyr SWG"

if [[ $SWG_RELEASE_SCRIPT ]]
then
    release_script=$SWG_RELEASE_SCRIPT
fi

FILE=/tmp/release-meting.mail

cat > $FILE << EOF
From: put.your@email.here
To: <release managers emails here>
Subject: Security issues report
MIME-Version: 1.0
Content-Type: text/html

<p>
Hi,<br/>
<br/>
The following report contains a list of pull-requests fixing <br/>
vulnerabilities that are being tracked by the security working group.
<br/>
<br/>
It contains three fields, the first column contains the embargo<br/>
period, the second the link for the pull-request with a brief<br/>
description and the third contains the branch which the pr was merged,<br/>
this is useful to know whether or not there is a release with this fix.<br/>
<br/>
</p>
EOF

$release_script -r -H >> $FILE
if [ $? -eq 1 ]
then
	exit 1
fi

cat >> $FILE << EOF

<p>
<br/>
Regards<br/>
</p>
EOF

# Uncomment the following line if you use msmtmp
#cat $FILE | /usr/bin/msmtp-enqueue.sh -oi -f put.your@email.here -t
