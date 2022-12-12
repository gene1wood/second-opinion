# Sept 7, 2017

* It looks like the `userinfo` database of users is empty at the point when the 
  `/userinfo` endpoint attempts to query it. It looks like this is because of 
  the chicken egg problem between the `provider` and the `authnbroker item`. So 
  I'm reworking the whole thing to only manifest a `provider` within an active 
  flask user query so that the `client_id` is available to pass. This doesn't 
  solve the question of how to create a `UserAuthnMethod` which depends on an 
  `srv` value which appears to supposed to be a `provider`, when creating a 
  `provider` requires passing an `AuthNBroker` which contains the `UserAuthnMethod`. 
  Chicken, egg.

# Sept 6,2017

* I had a malformed config.json with a different client ID. I've fixed and signed that json.
* I've updated the clientid in testrp to match. client id and client secret on testrp match config.json and credstash currently.
* I've broken all testrp rp logins somehow.
* As a result my testrp logins fail before reaching second opinion

# August 31, 2017

* Use this to workaround mfa : `/home/gene/code/github.com/gene1wood/second-opinion/second_opinion/get-sts-session.bash`
* I've found that [this](https://github.com/OpenIDC/pyoidc/blob/f2209472b44f5a812725b98c3835e0b22665010d/src/oic/utils/aes.py#L102) test fails causing auth to fail.
* I just began passing into the instantiation of `DuoAuthnMethod`, the value of `self.get_provider(self.get_userinfo())` for the `srv` argument (which is also new). Determine if this works.
* My theory is that iv and symkey are supposed to be consistent across calls by the user (and previously they were random strings generated on each call)
* If this turns out to be true, then my temporary static setting of symkey to `testestestestest` needs to instead be a value pulled from credstash.
* Determine if there's a version between the two commits called out in `requirements.txt` that will work.
* I think all my debug code is being applied to a detached head of pyoidc at some specific commit. Might be worth moving around in the commit history to see if that fixes things.



# August 11, 2017

* I login to SO get sent to duo prompt, enter code then, duo verify succeeds, cookies set set I'm redirected to /authorize and instead of checking my cookie and sending me on, I'm presented with the duo prompt again
* I'm trying to get the app.py:authorize endpoint to show me what's going on
* I want to know what's happening when `oic/provider.py` calls `authnres = self.do_auth`
* which calls `oauth2/provider.py`, but if any error were to occur in `do_auth` it wouldn't get back to me because all error info is thrown away and the user is just redirected
* gotta figure out how to add debug code to pyoidc such that when I `zappa update dev` my copy of pyoidc gets packaged and sent to AWS lambda, not the pypi pyoidc
* oh and I found a bug [here](https://github.com/mozilla-iam/testrp.security.allizom.org/blob/master/webserver_configurations/OpenID_Connect/Nginx/conf.d/second_opinion/openidc_second_opinion_layer.lua#L129)
  * `res, err, url, secondary.session = oidc.authenticate(secondary.opts, nil, secondary.session_opts)` should be `res, err, url, secondary.session = oidc.authenticate(secondary.opts, nil, nil, secondary.session_opts)`


# August 10, 2017

* second-opinion is deployed in infosec-dev. You can hit it at https://second-opinion.security.allizom.org/.well-known/openid-configuration
* deployment required newest botocore (without persistent cache). Without it `certify` domain name setup fails
* testrp is configured to use it
* You can test this at : https://ldap-second-opinion.testrp.security.allizom.org/
* When I log in, I get sent to auth0, auth, then end up logged in.
* A call is made by testrp to fetch the well-known config from second opinion
* No call is made to auth there though
* The debug logs on testrp openresty show an openidc lua authenticate call but I don't know what's happening under the hood
* Up next
* Add debug lines to `/usr/local/openresty/nginx/conf/conf.d/second_opinion/openidc_second_opinion_layer.lua` in order to better understand what's going into the second opinion authenticate call and what's getting returned
* Watch logs during login : `tail -f /usr/local/openresty/nginx/logs/*.log`
* Finally when this is working diff the live testrp config against what's in git to see if I fixed anything
* Also, make sure that whatever error condition that's happening and causing the lua openidc authenticate call to not return an `err` value can't happen again since this is a failure that allows a user in without auth
* Also it looks like maybe the testrp php tries to display `HTTP_OIDC_CLAIM_ACCESS_TOKEN` and `HTTP_OIDC_CLAIM_ID_TOKEN` header values on the page but they're not present, not sure why this is. Maybe because [of what I output?](https://github.com/mozilla-iam/testrp.security.allizom.org/blob/master/webserver_configurations/OpenID_Connect/Nginx/conf.d/second_opinion/openidc_second_opinion_layer.lua#L170-L177)


# July 25, 2017

DONE Resign signermap.json and upload new file and sig
DONE Redeploy with zappa to infosec-dev and figure out why gpg verification isn't working.
DONE I've just added public keys to signermap and i should see if that works
DONE Also, I thought the signer map showed who could sign lists of fingerprints in something. I feel like I've missed a level. If I add ulfr as a permitted signer for a given s3 directory, shouldn't he then be able to authorize an arbitrary set of signers?

# June 2, 2017



* Delete `second-opinion:client_secret` from infosec-dev credstash
* Generate a new clientid and secret with `add_client.py` and inject it into the credstash of the appropriate AWS account
* Update testrp `centos@testrp.security.allizom.org:/usr/local/openresty/nginx/conf/conf.d/second_opinion/second_opinion_options.lua` with the new cliend-id and secret and URL to the right second opinion (from the right AWS account)
* Maybe provision testrp to talk to both dev secondopinion and prod secondopinion (grey button and red button)
* Currently `add_client.py` doesn't do any of the gpg signing of config json containing client DB. Maybe add this or just document the process of copy pasting the output from add_client into the `config.json` and signing and uploading
* Add to `userinfo` some "comment" or "note" field that explains where the source of the group information is (the authorization json url)
* Confirm that the `userinfo` data structure we're sending complies to [the spec](http://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
* Then maybe unit tests?

# DONE

I've just created `add_client.py` but I'm realizing I can't use the `remove_env`
zappa thing to store a structured object.

So I need to access it in a signed object just like the group membership data

So I should skip straight to writing the code to
* set a URL in the remove_env config that points to a json file client DB
* set a URL in the remove_env config that points to a detached signature of that client DB json file
* check for the presence of cached versions of those files in s3, maybe checking for their date or just setting an expiration on the s3 objects so they self delete
* consider etag stuff so that you don't have to refetch the source URL over and over
* if they're expired or missing, fetch the files from the source URLs
  * Maybe kick this off as a background task somehow and use the cached, stale data that we have so we don't block on waiting for that network call
* validate the detached signature based on a list of identities also passed in `remote_env`
  * guess this is GPG and the identies are key fingerprints
* ingest the now validated config

Once I've got this update add_client.py to
* add a client to a local client db
    * fetch the client DB from s3
    * generate a new client
    * add it to the local client DB
* sign a local client db
* upload a local client Db and detached signature to s3

Then use add_client.py to publish a signed clientDB to S3

And fix the config.json files destined for https://github.com/mozilla/security-private/tree/master/infosec-internal-data to contain these URLs instead of structured data

Next do a similar thing for the group membership data structure

* Map out where everythings going to be hosted
  * environments : dev and prod
  * AWS Accounts : cloudtrail, infosec-prod, infosec-dev
  * resources : KMS key for credstash, dynamodb, lambda function + apigateway, signed json config, signed json rp authorization data for testrp, route53 name
* NO
    * Consider enabling the credstash kms key for say `infosec-prod` to be used by the cloudtrail AWS account [like this](https://aws.amazon.com/blogs/security/share-custom-encryption-keys-more-securely-between-accounts-by-using-aws-key-management-service/)