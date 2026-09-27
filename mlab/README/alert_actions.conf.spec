[mlab_ir]
param.base_url = <string>
* ir.mlab.sh base URL, e.g. https://ir.example.com
* The app token is read from storage/passwords (realm mlab, name ir_token).

param.severity = info|low|medium|high|critical
* ir.mlab.sh severity when the result has no severity/urgency field of its own.
* Default: medium

param._cam = <json>
* Common Action Model metadata: lets Splunk Enterprise Security offer the action as an adaptive response.
