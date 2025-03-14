#!/usr/bin/perl

use strict;
use HTTP::Tiny;

my $tenant = "<O365 TenantId>";
my $client_id = "981f26a1-7f43-403b-a875-f8b09b8cd720";
my $client_secret = "<see mfa_push.sh on how to create>";

my $scope = 'https://adnotifications.windowsazure.com/StrongAuthenticationService.svc/Connector/.default';
my $grant_type = 'client_credentials';

my ($user) = @ARGV;
die "Usage: $0 <user principal name>" unless $user;

my $token = "";
my $recurse_control = 0;

sub update_token {
	my $http = HTTP::Tiny->new();
	my $res = $http->post_form( "https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token", {
		client_id => $client_id,
		client_secret => $client_secret,
		scope => $scope,
		grant_type => $grant_type
	} );
	die "Error: unhandled HTTP/$res->{status}" unless $res->{success};

	return $1 if $res->{content} =~ /{.*"access_token":"([^"]+)".*}/;
	die "Error: no token received\n $res->{content}";
}

sub request_mfa {

	my $XML = <<"EOF";
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

	$token = update_token unless $token;
	my $res = { status => '' };
	my $http = HTTP::Tiny->new();
	do {
		$token = update_token if ( $res->{status} eq '401');
		$res = $http->post( 'https://adnotifications.windowsazure.com/StrongAuthenticationService.svc/Connector/BeginTwoWayAuthentication', {
				headers => {
					"Authorization" => "Bearer ${token}",
					"Content-Type" => "application/xml"
				},
				content => $XML
			} );
	} while ( $res->{status} eq '401' && $recurse_control++ <= 1 );
	$recurse_control = 0;

	die "Error: unhandled HTTP/$res->{status}" unless $res->{success};

	$res->{content} =~ m/<AuthenticationResult>(.*)<\/AuthenticationResult>.*<UserPrincipalName>(.*)<\/UserPrincipalName>/i;
	if ( lc($1) eq "true" && lc($user) eq lc($2) ) {
			return "ok"
	}else{
		return "reject"
	}
}

print request_mfa;
