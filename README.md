Second Opinion was an OpenID Connect OpenID Provider (OP) which used Duo Security for authentication and an out-of-band authorization provider for authorization. It sought to provide a second opinion to a relying party (RP) after their user has authenticated with the primary OP and the RP has received back authorization claims from the primary OP. 

# Status : Deprecated

This project never made it. The design idea is sound but couldn't push it past the finish line and get adoption.

# Design

## Summary & Scope

This document describes a model of authentication and authorization that would improve the security of a relying party or website through the use of a second opinion regarding a users authentication and authorization. This model would be usable by any relying party that needs high security.

## Second Opinion Model of Authentication and Authorization

### Current Status

This was a project from 2017 which never made it off the ground and is now deprecated. The code is now archived.

### The Problem

When a single serial chain of systems is used to authenticate or authorize a user to a resource, a security breach of any system in that chain could enable an attacker to gain unauthorized access to that resource. For example when a website depends on Auth0 to authorize a user, and Auth0 depends on an LDAP server to provide the user's group membership information, and the LDAP server gets that group membership data from the mozillians.org website, a security breach of any of those systems could result in unauthorized access. For example, an attacker could compromise mozillians.org and add their user account into a group like `firefox-accounts-administrative-access`, elevating their privileges. This type of problem potentially exists both for authentication and authorization.

### The Second Opinion Model Solution

#### What we do currently

The way that we currently mitigate this risk, specifically for relying parties that handle data classified at a high level of sensitivity, is that the relying party queries two distinct unrelated systems to verify that both systems agree that a user is authenticated. These two distinct systems are currently Okta/Auth0 for the username and password and Duo for the multi factor authentication code. For these high security relying parties, the call to Duo for the multi factor authentication challenge is done by the relying party, not by Okta/Auth0. The result of this is that a security breach of any component in the Okta/Auth0, LDAP chain could result in a fraudulent response to the relying party that an attacker is authenticated. It, however, would not result in the second opinion from Duo indicating that the attacker is authenticated.

This second opinion check is only done for authentication, not authorization.

#### What we could do better

We could apply this same type of solution to the question of authorization for these high security relying parties. Currently relying parties get only one opinion about user group membership which comes from the Okta/Auth0, LDAP chain. One way to do this would be to create a new, simple, system that stored group membership information for a subset of groups which we'd decided were "high security" separately from the Okta/Auth0 LDAP chain. These "high security" groups would be ones which were used by relying parties to grant significant administrative rights to users in their systems.

### Proposed Implementation

In order to reduce the number of calls that the relying party needs to make during authentication and authorization and to simplify the process of getting the second opinion, we could create an out-of-band authentication and authorization provider. This OIDC provider would send the user on to Duo to authenticate with their multi-factor authentication device, then the out-of-band provider would fetch the authorization (group membership) information from the second opinion group datastore and include it as claims in the OIDC response to the relying party.

[![Second Opinion Model of Authentication and Authorization](assets/Second%20Opinion%20Model%20of%20Authentication%20and%20Authorization.png)](assets/Second%20Opinion%20Model%20of%20Authentication%20and%20Authorization.pdf)

The relying party would then take these 4 pieces of information to make it's decision whether or not to grant the user access

* Okta/OAuth's assertion that the user is authenticated
* Okta/OAuth's claims about group membership
* Out-of-band provider's assertion that the user is authenticated to Duo
* Out-of-band provider's claims about group membership

The first two pieces of information would be asserted by Okta/Auth0 and the second two would be asserted independently by the out-of-band provider. These two independent assertions are key to providing a higher level of security.

Initially the management of this second opinion group datastore would be a labor intensive/manual process based on the assumption that changes to group membership would be infrequent and the number of groups would be small. The labor of this process would be due to the fact that we could not use any existing authentication system to govern access to the datastore (for obvious reasons). This process, for example, could involve bugzilla tickets requesting changes that infosec team personnel manually rendered in the datastore. If changes to group membership became more frequent or more groups were added resulting in more frequent modifications to this datastore, a better administration process would need to be established.

It may also be desirable to whitelist all high security relying parties (RPs which are doing a second opinion call that causes Duo MFA authentication) in Auth0 to prevent users from having to provide a Duo MFA code twice (once to Duo after authenticating to Auth0, and then a second time when the call to the out-of-band provider is made). Care would need to be taken so as to avoid a situation where the Auth0 whitelist incorrectly thinks that the RP will take care of Duo MFA authentication through a second opinion, and the RP incorrectly thinks that Auth0 will take care of Duo MFA authentication, thus resulting in a user not being prompted for their MFA code.

#### Defense against a bad actor

For this second opinion model to be effective the administrators of the second opinion system need to be distinct from the administrators of the primary authentication system (Okta/Auth0, LDAP). This is so that an administrator who's account is compromised or operates as a bad actor will not be able to bypass the other system.

#### Pros and Cons

* Pro : High security relying parties need only make two calls (to Auth0/Okta and to out-of-band provider), just as they do now (to Auth0/Okta and to Duo)
* Pro : High security relying parties need only speak OIDC now instead of both OIDC and Duo API potentially simplifying RP code
* Pro : An attacker would now have to compromise both systems or administrator accounts of both systems to gain access to a high security relying party. This would require compromising (Okta/Auth0 or LDAP or mozillians.org) and (out-of-band provider or Duo or second opinion datastore)
* Con : The process of modifying the second opinion group datastore would be manual and not self-service
* Con : The out-of-band provider would have to be developed

#### The second opinion group datastore

This datastore could be something as simple as a json file hosted on a server or in a sequestered/dedicated AWS account or a simple web service REST API in front of a database on a server or in a dedicated AWS account. We would most likely start with the simplest solution and then improve or change it if changes to group membership or the number of groups increased.

### The Name

The model is called "Second Opinion" as it provides an RP with a second opinion on the validity of a user in the same way that a patient would seek a second opinion from a physician.

# Setup

## Create IAM Role for Lambda Function

Deploy the `second_opinion_lambda_execution_role.json` CloudFormation template

## Push Credentials into Credstash

Assuming you have your Duo secrets stored in 3 files :

    region="us-west-2"
    credstash_key_id="`aws --region $region kms list-aliases --query "Aliases[?AliasName=='alias/credstash'].TargetKeyId | [0]" --output text`"
    role_arn="`aws iam get-role --role-name second_opinion --query Role.Arn --output text`"
    constraints="EncryptionContextEquals={application=second-opinion}"
    akey="`python -c "import os, hashlib; print hashlib.sha1(os.urandom(32)).hexdigest()"`"
    
    # Grant the second-opinion IAM role permissions to decrypt
    aws kms create-grant --key-id $credstash_key_id --grantee-principal $role_arn --operations "Decrypt" --constraints $constraints --name second-opinion

    # Add a credential to the store
    echo "$akey" | tr -d '\n' | credstash --region $region put --autoversion second-opinion:duo:akey - application=second-opinion
    cat ikey.txt | tr -d '\n' | credstash --region $region put --autoversion second-opinion:duo:ikey - application=second-opinion
    cat skey.txt | tr -d '\n' | credstash --region $region put --autoversion second-opinion:duo:skey - application=second-opinion
    cat data-host.txt | tr -d '\n' | credstash --region $region put --autoversion second-opinion:duo:data-host - application=second-opinion

Note : Since KMS grants are only eventually consistent, second-opinion won't immediately have access to these credstash credentials after granting it access to them

# In my deployment to infosec-isolated, I'm here. I'm testing ACM in infosec-dev

## Generate an ACM Certificate

Instead of using Lets Encrypt, as [the certificate renewal process requires downtime](https://github.com/Miserlou/Zappa/issues/1016), request issuance of an ACM Certificate in `us-east-1`

Once the certificate is issued, determine the ARN of the cert and configure it in `zappa_settings.json`

## x
  

## To create OIDC OP Keys

1. Generate keys and store the resulting JSON in credstash


    region="us-west-2"
    credstash_key_id="`aws --region $region kms list-aliases --query "Aliases[?AliasName=='alias/credstash'].TargetKeyId | [0]" --output text`"

    # Add a credential to the store
    python tools/generate_new_op_keys.py | credstash --region $region put --autoversion second-opinion:opkeys - application=second-opinion

2. Generate a SECRET_KEY for Flask


    region="us-west-2"
    credstash_key_id="`aws --region $region kms list-aliases --query "Aliases[?AliasName=='alias/credstash'].TargetKeyId | [0]" --output text`"
    echo "import string, random;print(''.join(random.SystemRandom().choice(string.printable) for _ in range(24)))" | python | credstash --region $region put --autoversion second-opinion:secret-key - application=second-opinion


# Run locally

    FLASK_APP=app.py AWS_DEFAULT_PROFILE="infosec-dev-admin" venv-zappa/bin/flask run

## RP

    PATH=/usr/local/openresty/nginx/sbin:$PATH
    cd /usr/local/openresty/nginx
    pkill nginx; nginx -p `pwd`/ -c /usr/local/openresty/nginx/conf/nginx.conf

## DNS

Create DNS entries for the RP and OP in route53

# Deploy with zappa

* Create a virtualenv for zappa
* Install zappa into the virtualenv and install second-opinion requirements and zappa (into the same virtualenv)

      venv-zappa2/bin/pip install -r ../second_opinion/requirements.txt

* Deploy?

      . ../.sandbox/venv-zapp2/bin/activate
      zappa deploy dev
      zappa tail dev

* Certify

      ../.sandbox/venv-zappa2/bin/zappa certify

* Create route53 CNAME
 * When we were using Lets Encrypt this was to workaround https://github.com/Miserlou/Zappa/issues/762
 * Now using ACM the Certify should fix things


# Usage

## Create new RP clients

1. Generate a client_id and secret, storing the secret in credstash


    $python tools/add_client.py
    
    Enter redirect_uris one at the time, end with a blank line: 
    ?: https://rp.example.com/second-opinion/redirect_uri
    ?: 
    Enter policy_uri or just return: 
    Enter logo_uri or just return: 
    Enter jwks_uri or just return: 
    
    Share the following information with the client through a secure channel
    
    Client ID : S7Zje9nuBfyb
    Client Secret : b1b01ccc92c38231ff7b0c359cfda6f3fae56e4eba610ef3ff7c9bff
    Allowed redirect URIs: [['https://rp.example.com/second-opinion/redirect_uri', None]]
    
    Add the following new client information to the config
    {
      "OP_CLIENT_DB": {
        "S7Zje9nuBfyb": {
          "redirect_uris": [
            [
              "https://rp.example.com/second-opinion/redirect_uri", 
              null
            ]
          ], 
          "client_salt": "Cf9hEwEs", 
          "client_id": "S7Zje9nuBfyb",
          "token_endpoint_auth_method":"client_secret_post"
        }
      }
    }
    
    Would you like to store the client secret in credstash in us-west-2?y
    Enter MFA code: 
    second-opinion:client_secret:S7Zje9nuBfyb has been stored
2. Store the resulting configuration in the [infosec-internal-data](https://github.com/mozilla/security-private/tree/master/infosec-internal-data) repo in the [dev](https://github.com/mozilla/security-private/tree/master/infosec-internal-data/second-opinion/dev) or [prod](https://github.com/mozilla/security-private/tree/master/infosec-internal-data/second-opinion/prod) directories. This config will be accessed by zappa via [remote_env](https://github.com/Miserlou/Zappa#remote-environment-variables)
3. Deploy the `config.json` to the `infosec-internal-data` S3 bucket.


## Signing hierarchy

second-opinion uses a hierarchy of GPG signatures to ensure the validity of both
configuration files and authorization data. This hierarchy consists of 4 levels.

The actors in this hierarchy are
* signing root authority : This is a single GPG keypair stored in a safe
* root signers : This is a set of signers for each functional area of Mozilla that wants to use second opinion. This list should only change when an entirely new functional area of Mozilla begins using second opinion which should be infrequent.
* client signers : These are the signers that a given Mozilla functional area administrator wants to authorize to manage a one of their clients authorization data. As each functional area's list of client signers is managed entirely within that functional area, the list of client signers could change frequently or infrequently depending on the internal practices of the functional area admins

### Signing root authority

The root of the signing authority comes from a GPG keypair with the fingerprint
hard coded into second-opinion. This can be found in the `SIGNING_ROOT_AUTHORITY_FINGERPRINTS`
constant.

#### Example signing root authority

    {"s3://example-bucket/signer-map.json" : ["12345678"]}

### Root signer map

The next step down the hierarchy comes from the `SIGNER_MAP_URL` which is a URL
pointing to a `json` map of URLs and their associated authorized signer fingerprints.
This map, in its entirety, is in turn signed by the root authority and verified.
This map is used to enumerate the authorized signers of both the config files and the client signer maps

#### Example root signer map

`s3://example-bucket/signer-map.json` signed by `12345678`

    {"signer_map": {
        "s3://second-opinion-bucket/configs/": ["90ABCDEF"],
        "s3://foo-org-bucket/": ["01234567"],
        "s3://bar-org-bucket/so/": ["890ABCDE"],
    }}

### Config files and client signer maps

The third level down contains config files and lists of signers that can sign authorization data.

#### Config files

The second opinion config files are signed by a signer authorized in the root signer map. The files contain the client IDs and each client's authorization data url and client signer map url (note this is a signer map specific to a given client)

##### Example config file

`s3://second-opinion-bucket/configs/config.json` signed by `90ABCDEF`

    {
      "OP_AUTHORIZATION_URLS": {
        "abCDefGHijKL": {
          "signer_map_url" : "s3://foo-org-bucket/signer-map.json",
          "signer_map_sig_url" : "s3://foo-org-bucket/signer-map.json.sig",
          "authorization_data_url" : "s3://foo-org-bucket/baz-client/authorization.json",
          "authorization_data_sig_url" : "s3://foo-org-bucket/baz-client/authorization.json.sig"
        },
        "mnOPqrSTuvWX": {
          "signer_map_url" : "https://bar.example.com/so/signers.json",
          "signer_map_sig_url" : "https://bar.example.com/so/signers.json.sig",
          "authorization_data_url" : "https://bar.example.com/qux-client/auth.json",
          "authorization_data_sig_url" : "https://bar.example.com/qux-client/auth.json.sig"
        }
      }
    }

#### Client signer maps

Each functional area hosts it's own signer map. This allows for self service addition and removal of authorized signers of the authorization data for clients. 

##### Example client signer map
`s3://foo-org-bucket/signer-map.json` signed by `01234567`

    {
      "signer_map": {
        "s3://foo-org-bucket/baz-client/": [
          "F0123456",
          "7890ABCD"
        ]
      }
    }

#### Authorization data

Each client can have a distinct authorization data file, or clients can share an authorization data file. This authorization data should match the authorization data stored in the primary authentication provider. The signers detailed in the client signer map can sign the authorization data file.

##### Example authorization data
`s3://foo-org-bucket/baz-client/authorization.json` signed by `F0123456`

    {
      "groups": {
        "team_finance": [
          "alice@example.com",
          "john@example.com",
          "jane@example.com"
        ]
      }
    }


## How to sign files

    gpg --default-key 0x85914504D0BFA220E93A6D25B40E5BDC92377335 --output signer-map.json.sig --detach-sig signer-map.json
    gpg --default-key 0x85D77543B3D624B63CEA9E6DBC17301B491B3F21 --output config.json.sig --detach-sig config.json



# Deprecated

## Chalice

This project is no longer using Chalice.

### To prebuild module extensions on Amazon Linux

https://markn.ca/2015/10/python-extension-modules-in-aws-lambda/
https://github.com/awslabs/chalice/issues/265
http://stackoverflow.com/q/36468984/168874

```
virtualenv venv; . venv/bin/activate
sudo yum -y groupinstall "Development Tools" && sudo yum -y install libffi-devel openssl-devel
pip install boto3 credstash duo_web
```

then pull down the resulting built packages

http://chalice.readthedocs.io/en/latest/topics/packaging.html#rd-party-packages

```
ec2host=x
mv -v .chalice/venv .chalice/venv.local
mkdir .chalice/venv
rsync -Lav ec2-user@$ec2host:venv/ .chalice/venv/
mkdir vendor
rsync -Lav ec2-user@$ec2host:/usr/lib64/libssl.so.10 vendor/libssl.so.1.0.0
rsync -Lav ec2-user@$ec2host:/usr/lib64/libcrypto.so vendor/libcrypto.so.1.0.0
```

### Challenges

Intermittently encountering a scenario where boto3 throws a ClientError which chalice passes to click which in turn tries to encode it as an ascii string which fails because of unicode characters in the boto3 exception payload. This may relate to this [bug](http://bugs.python.org/issue2517).

## To get manual certs for testing


    rp_name=rp.example.com
    op_name=op.example.com
    email=user@example.com
    
    virtualenv venv-getcert
    mkdir getcert
    venv-getcert/bin/pip install certbot certbot-route53 git+https://github.com/gene1wood/botocore.git@persistent-credential-cache-with-serialization
    venv-getcert/bin/certbot certonly -n --agree-tos --email $email -a certbot-route53:auth -d $rp_name -d $op_name --config-dir getcert/ --work-dir getcert/ --logs-dir getcert/
