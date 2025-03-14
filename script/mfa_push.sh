#!/bin/sh
#
# In Powershell:
#
# Connect-MgGraph -Scopes 'Application.ReadWrite.All'
# $servicePrincipalId = (Get-MgServicePrincipal -Filter "appid eq '981f26a1-7f43-403b-a875-f8b09b8cd720'").Id
# $params = @{
#	passwordCredential = @{
#		displayName = "My Application MFA"
#	}
# }
# $secret = Add-MgServicePrincipalPassword -ServicePrincipalId $servicePrincipalId -BodyParameter $params
#

tenant="<O365 TenantId>"
client_id="981f26a1-7f43-403b-a875-f8b09b8cd720"
client_secret="<see secret from comment above>"

scope='https://adnotifications.windowsazure.com/StrongAuthenticationService.svc/Connector/.default'
grant_type='client_credentials'

token_file="/tmp/azure.client_token"
response="/tmp/azure.response"

if [ "$#" -lt 1 ] ; then
	echo "Usage: $0 <user>"
	exit 1
fi

user=$(echo $1 | tr '[:upper:]' '[:lower:]')
token_updated=""
token=""

update_token()
{   
	token=$(curl -s -X POST -H "Content-Type: application/x-www-form-urlencoded" "https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token" \
	 --data-urlencode "client_id=${client_id}" \
	 --data-urlencode "client_secret=${client_secret}" \
	 --data-urlencode "scope=${scope}" \
	 --data-urlencode "grant_type=${grant_type}" | jq -r '.access_token|values')

	if [ -z "${token}" ] ; then
		echo "Error: something went wrong"
		exit 1
	fi
	echo "${token}" > "${token_file}"
	chmod 600 "${token_file}"
	token_updated=1
}

get_token()
{
	if [ ! -f "${token_file}" ] ; then
		update_token
	else
		token=$(cat "${token_file}")
	fi
}

request_mfa()
{

    XML=$(cat <<EOF
        <BeginTwoWayAuthenticationRequest>
            <Version>1.0</Version>
            <UserPrincipalName>$user</UserPrincipalName>
            <Lcid>en-us</Lcid>
            <AuthenticationMethodProperties xmlns:a="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
                <a:KeyValueOfstringstring>
                    <a:Key>OverrideVoiceOtp</a:Key>
                    <a:Value>false</a:Value>
                </a:KeyValueOfstringstring>
            </AuthenticationMethodProperties>
            <ContextId>eba037c8-2b18-4852-8548-f34b7c01fae6</ContextId>
            <SyncCall>true</SyncCall>
            <RequireUserMatch>true</RequireUserMatch>
            <CallerName>radius</CallerName>
            <CallerIP>UNKNOWN:</CallerIP>
        </BeginTwoWayAuthenticationRequest>
EOF
    )

    if [ -z "${token}" ] ; then
        get_token
    fi

	error=$(curl -s -X POST -H "Authorization: Bearer ${token}" -H "Content-Type: application/xml" -w "%{http_code}" -o "${response}" \
            'https://adnotifications.windowsazure.com/StrongAuthenticationService.svc/Connector/BeginTwoWayAuthentication' \
            --data "$XML"
        )

	if [ "$error" = "401" -a -z "${token_updated}" ] ; then
		update_token
		request_mfa
	elif [ "$error" != "200" ] ; then
		echo "Error: unhandled HTTP ${error}"
        cat "${response}"
        exit 1
	fi
}

request_mfa

UPN=$(cat /tmp/azure.response | sed -e 's/^.*<UserPrincipalName>\(.*\)<\/UserPrincipalName>.*$/\1/gi' | tr '[:upper:]' '[:lower:]')
RES=$(cat /tmp/azure.response | sed -e 's/^.*<AuthenticationResult>\(.*\)<\/AuthenticationResult>.*$/\1/gi' | tr '[:upper:]' '[:lower:]')

if [ -n "${RES}" ] && [ -n "${UPN}" ] ; then
    if [ "${RES}" = "true" ] ; then
        if [ "${UPN}" = "${user}" ] ; then
            rm -f "${response}"
            echo "Success: User authenticated using MFA"
            exit 0
        else
            echo "Error: MFA received but user is missing"
        fi
    else
        echo "Error: MFA not successful"
    fi
else
    echo "Error: no MFA received"
fi

cat "${response}"
exit 1
