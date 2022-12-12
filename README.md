Second Opinion was an OpenID Connect OpenID Provider (OP) which used Duo Security for authentication and an out-of-band authorization provider for authorization. It sought to provide a second opinion to a relying party (RP) after their user has authenticated with the primary OP and the RP has received back authorization claims from the primary OP. 

# Status : Deprecated

This project never made it. The design idea is sound but couldn't push it past the finish line and get adoption.

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
