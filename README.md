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