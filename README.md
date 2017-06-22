Second Opinion is an OpenID Connect OpenID Provider (OP) which uses Duo Security for authentication and an out-of-band authorization provider for authorization. It seeks to provide a second opinion to a relying party (RP) after their user has authenticated with the primary OP and the RP has received back authorization claims from the primary OP. 

# Status

This project is pre-alpha currently.

# Setup

## To put credentials into credstash

Assuming you have your Duo secrets stored in 4 files :

    region="us-west-2"
    credstash_key_id="`aws --region $region kms list-aliases --query "Aliases[?AliasName=='alias/credstash'].TargetKeyId | [0]" --output text`"
    role_arn="`aws iam get-role --role-name second_opinion --query Role.Arn --output text`"
    constraints="EncryptionContextEquals={application=second-opinion}"
    
    # Grant the second-opinion IAM role permissions to decrypt
    aws kms create-grant --key-id $credstash_key_id --grantee-principal $role_arn --operations "Decrypt" --constraints $constraints --name second-opinion

    # Add a credential to the store
    cat akey.txt | tr -d '\n' | credstash --region $region put --autoversion second-opinion:duo:akey - application=second-opinion
    cat ikey.txt | tr -d '\n' | credstash --region $region put --autoversion second-opinion:duo:ikey - application=second-opinion
    cat skey.txt | tr -d '\n' | credstash --region $region put --autoversion second-opinion:duo:skey - application=second-opinion
    cat data-host.txt | tr -d '\n' | credstash --region $region put --autoversion second-opinion:duo:data-host - application=second-opinion

Note : Since KMS grants are only eventually consistent, second-opinion won't immediately have access to these credstash credentials after granting it access to them

## To get certs


    rp_name=rp.example.com
    op_name=op.example.com
    email=user@example.com
    
    virtualenv venv-getcert
    mkdir getcert
    venv-getcert/bin/pip install certbot certbot-route53 git+https://github.com/gene1wood/botocore.git@persistent-credential-cache-with-serialization
    venv-getcert/bin/certbot certonly -n --agree-tos --email $email -a certbot-route53:auth -d $rp_name -d $op_name --config-dir getcert/ --work-dir getcert/ --logs-dir getcert/

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

* Certify

      ../.sandbox/venv-zappa2/bin/zappa certify
    
* Deploy?

      . ../.sandbox/venv-zapp2/bin/activate
      zappa deploy dev

* Create route53 CNAME to workaround https://github.com/Miserlou/Zappa/issues/762

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
configuration files and authorization data. This hierarchy consists of 3 levels.

### Signing root authority

The root of the signing authority comes from a GPG keypair with the fingerprint
hard coded into second-opinion. This can be found in the `SIGNING_ROOT_AUTHORITY_FINGERPRINTS`
constant.

### Signer map

The next step down the hierarchy comes from the `SIGNER_MAP_URL` which is a URL
pointing to a `json` map of URLs and their associated authorized signer fingerprints.
This map, in its entirety, is in turn signed by the root authority and verified.

### Config files and authorization data

Finally the bottom of the hierarchy are both config files for second-opinion
and authorization data for RPs. These data are hosted elsewhere and referenced
by URL. The data is fetched from the URL, and the signature is verified to be
valid and signed by an authorized signer in the SIGNER_MAP.

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