# pydentitester
A (Relatively) simple flask-based tester for various authN/authZ protocols.

Things I intend to add when I get time:

* More OIDC flows
* Eventually SCIMv2 client support
* Eventually LDAPv3 client support

Things I'll try to get done after that:

* An extremely basic OIDC provider, like as bare bones as it gets
* An extremely basic SCIMv2 
* An extremely basic LDAPv3 server- it will literally just return rootDSE, maybe I'll make it more robust later?

Maybe someday I'll make it "Production grade" by moving it out of Flask and on to an actual WSGI setup, but the use case for all of this is intended for very low volume usage and spinning up/spinning down as needed.