# Migrating from Vault Enterprise to OSS

This guide is the result of a lot of work that came from learning the hard way that Vault Enterprise is not worth the large licensing costs that Hashicorp charges, and that with the proper team and configurations, it is quite easy to run reliable and effective Vault clusters.  Unless an organization requires FIPS compliance, there is little that Vault Enterprise gives you that cannot be achieved with Vault OSS with a bit of dedication.

The code snippets in this guide are from [https://github.com/nomeelnoj/vault-cluster](https://github.com/nomeelnoj/vault-cluster), a Terraform module that works for both Vault OSS and Vault Enterprise.

**NOTE: This guide assumes a running vault cluster on at least 3 ARM-based Ubuntu nodes in AWS, configured by Terraform using an autoscaling group and launch template with `user_data`. Steps will likely be different for other platforms.**

Migrating from Enterprise to OSS is possible, but requires a bit of manual intervention.  The reason we cannot do this easily with terraform is because nodes from an OSS cluster cannot join an Enterprise cluster, and vice versa.  However, on a running node, you can replace the vault binary and if done properly, you will simply lose access to enterprise features.

**NOTE: There are some enterprise features that are enabled by default that will prevent OSS from working properly if not handled correctly.  Replacing the binary without first checking for these will result in a Vault that is unable to properly unseal. Please make sure to read [Enterprise Only Features](#enterprise-only-features) below.**

## Enterprise Only Features

Vault Enterprise offers many features that are not available in the OSS version, including but not limited to:

* Sealwrapping
* Automated Raft Snapshots Stored in S3
* Namespaces
* HSM Integration support
* Many others

If you are leveraging Vault Enterprise-only features, you will likely need to disable or remove them before you can move to Vault OSS.  In most cases, migrating to OSS will simply remove your access to these types of features, but depending on the feature (like Seal Wrap), you may be stuck with an unsealable Vault OSS cluster when you are done.  Since this document is written based on personal experience, it will only cover how to remove the Enterprise features that were used, rather than include speculation that may not work in actuality.

### Disable Sealwrapping

Vault Enterprise has a feature called [**Seal Wrap**](https://www.vaultproject.io/docs/enterprise/sealwrap).  Seal wrap wraps supporting seals in an extra layer of encryption.  So, the KMS seal wil be wrapped in an additional layer of encryption that Vault OSS cannot decrypt, resulting in a cluster with data that cannot be decrypted, or "unsealed".

This module disables seal wrapping by default so you should only have to confirm that seal wrapping is disabled by looking at `/etc/vault.d/vault.hcl` and making sure that `disable_sealwrap = true` is set.

However, if seal wrap is enabled and you need to migrate away from OSS, here are the steps:

1. Log into AWS and update the cluster autoscaling group by suspending the processes so it will not replace unhealthy nodes or terminate instances (essentially locking the ASG to the current nodes).
2. SSH into each of the vault servers, and run `vault status` to identify which server is the active node, or leader.
3. On the two **standby nodes**, update the vault config (loaded at runtime so it's ok) and then stop vault:

        echo "disable_sealwrap = true" >> /etc/vault.d/vault.hcl
        systemctl stop vault

4. On the leader node, perform almost the same steps, but restart vault instead of stopping it.

        echo "disable_sealwrap = true" >> /etc/vault.d/vault.hcl
        systemctl restart vault

5. Immediately go to the other two nodes and start vault back up

        systemctl start vault

6. Run `vault status` to ensure that the cluster is healthy.  The sealwrap is now disabled, so you can replace the enterprise binary with the OSS binary and update the terraform.  Specific steps in the next section.

7. Make sure to go back into AWS and unsuspend the ASG so that the HA and reliability tools we have in place continue to function.

**IMPORTANT NOTE: Disabling seal wrapping is is a lazy downgrade; as keys are accessed or written their seal wrapping status will change. If seal wrap is leveraged, after disabling it is prudent to access all seals that were wrapped so they are properly downgraded and the wrap is removed. If this step is not completed, the OSS cluster will be inaccessible.**

### Automated Raft Snapshots

Vault Enterprise includes a nice feature for automating backups called [Automated Integrated Storage Snapshots](https://developer.hashicorp.com/vault/docs/enterprise/automated-integrated-storage-snapshots).  This is more of a convenience feature, as achieving daily backups on OSS is relatively straightforward, assuming you have the proper configurations in place.  The [terraform object](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/resources/raft_snapshot_agent_config) that configures the auto-snapshots can be removed--the steps below will show how to accomplish daily snapshots without this object.

#### Creating an Automated Snapshot Workflow

Creating this workflow is actually relatively straightforward, but requires a few extra steps that might not be part of a normal Vault cluster Terraform module or configuration.

In order to automate snapshots, the following items are needed:

1. A vault role that has permissions to take snapshots
2. An AWS IAM role binding for the Vault nodes to be able to authenticate as this role
3. A cronjob script that takes the snapshots and uploads them to S3

Assuming the Vault nodes already have a bound IAM instance profile, we can leverage that along with a Vault role that will allow us to take snapshots.

The snapshot command below requires authentication to Vault, and we only want to run it on the leader/active node.  Therefore, we need the above items.

```console
vault operator raft snapshot save > $(date).snap
```

##### Creating the Resources

First, we need the Vault role. This role will be bound to the IAM principal that is used for the Vault nodes themselves.

**NOTE: The IAM Role associated with the Vault nodes MUST have `s3:PutObject` permissions on the S3 bucket where you intend to store raft snapshots.  If the bucket is encrypted with KMS, this role must also be able to use the KMS key to encrypt data uploaded to the bucket.**

The Terraform snippet below will create what is needed:

```hcl
data "vault_policy_document" "snapshotter" {
  rule {
    path         = "/sys/storage/raft/snapshot"
    capabilities = ["read"]
  }
  rule {
    path         = "/sys/storage/raft/configuration"
    capabilities = ["list", "read"]
  }
}

resource "vault_policy" "snapshotter" {
  name   = "snapshotter"
  policy = data.vault_policy_document.snapshotter.hcl
}

resource "vault_aws_auth_backend_role" "snapshotter" {
  backend                  = vault_auth_backend.aws.path
  role                     = "snapshotter"
  auth_type                = "iam"
  bound_iam_principal_arns = [var.snapshotter_role_arn]
  token_ttl                = 900
  token_max_ttl            = 900
  token_policies           = [vault_policy.snapshotter.name]
}
```

The above snippet assumes it is part of a module that includes the base config for any and all vault clusters that may be created.  It requires a single `variable`, the ARN of the role that is assigned to the Vault nodes:

```hcl
# This is incomplete code
module "vault_base_config" {
  source               = "../../../../modules/vault/vault-base-config"
  snapshotter_role_arn = "arn:aws:iam::0123456789:role/vault-cluster-dev"
}
```

Once we have the Vault role itself configured in Vault and bound to the IAM role on the Vault nodes, we can authenticate using the AWS auth method inside of a cronjob and take snapshots.

**NOTE: Since we configure all of our Vault nodes with Terraform and templated `user_data`, the syntax of the below code may look funny.  We have to take care to escape the code properly as it first gets templated through Terraform and into the `user_data` script that runs at boot on any Vault node, and then ensure that the data that gets written to the Cronjob is a proper script that can run. The code below is actually itself templated, and is therefore an argument into the `templatefile` function to populate the `user_data`.  Depending on how you are populating `user_data`, you may need to tweak it.**

The files needed to template this into the `user_data` correctly are below.  Note that `module.backups.bucket` is an S3 module output that represents the name of the S3 bucket we intend to use to store backups.

```hcl
# locals.tf
locals {
  userdata_values = {
    
    region          = var.aws_region
    tag_key         = var.tag_key
    tag_value       = var.tag_value
    leader_hostname = coalesce(var.leader_hostname, "vault.${var.env}.${local.hosted_zone}"

    # ... removed for brevity

    snapshot_config = length(
      regexall(
        "vault-enterprise", var.vault_binary
      )
    ) > 0 ? "" : <<EOT
cat <<-EOF > /etc/cron.daily/vault_snapshot
#!/bin/bash

TOKEN=\$(vault login -method=aws -field=token role=snapshotter)

export VAULT_TOKEN="\$${TOKEN}"

IMDS_TOKEN=\$( curl -Ss -H "X-aws-ec2-metadata-token-ttl-seconds: 30" -XPUT 169.254.169.254/latest/api/token )
INSTANCE_ID=\$( curl -Ss -H "X-aws-ec2-metadata-token: \$${IMDS_TOKEN}" 169.254.169.254/latest/meta-data/instance-id )

LEADER_ID=\$(vault operator raft list-peers | grep leader | awk '{print \$1}')

if [[ "\$${INSTANCE_ID}" == "\$${LEADER_ID}" ]]; then
  DATE=\$(date +%Y-%m-%d-%H-%M-%S)
  FILENAME="vault-snapshot-\$${DATE}Z.snap"
  vault operator raft snapshot save \$${FILENAME}
  aws s3 cp "\$${FILENAME}" "s3://${module.backups.bucket}"
  rm "\$${FILENAME}"
fi
EOF
chmod +x /etc/cron.daily/vault_snapshot
EOT
  }
}
```

This is passed into the `launch_template` as follows:

```hcl
# launch_template.tf
data "cloudinit_config" "userdata" {
  gzip          = true
  base64_encode = true

  part {
    content_type = "text/x-shellscript"
    filename     = "user_data.sh"
    content      = templatefile("${path.module}/templates/userdata.sh.tpl", local.userdata_values)
  }
}

resource "aws_launch_template" "default" {
  # ... removed for brevity
  user_data = data.cloudinit_config.userdata.rendered
}
```

To round this out, here is a snippet of the `userdata.sh.tpl` file that will accept this input:

```sh
# templates/userdata.sh.tpl
cat << EOF > /etc/vault.d/vault.hcl
disable_performance_standby = true
ui               = true
disable_mlock    = true
disable_sealwrap = true
storage "raft" {
  path    = "/opt/vault/data"
  node_id = "$instance_id"
  retry_join {
    auto_join               = "provider=aws region=${region} tag_key=${tag_key} tag_value=${tag_value}"
    auto_join_scheme        = "https"
    leader_tls_servername   = "${leader_hostname}"
    leader_ca_cert_file     = "/opt/vault/tls/vault-ca.pem"
    leader_client_cert_file = "/opt/vault/tls/vault-cert.pem"
    leader_client_key_file  = "/opt/vault/tls/vault-key.pem"
  }
}

cluster_addr = "https://$local_ipv4:8201"
api_addr     = "https://${leader_hostname}"

listener "tcp" {
  address                          = "0.0.0.0:8200"
  tls_disable                      = false
  tls_cert_file                    = "/opt/vault/tls/vault-cert.pem"
  tls_key_file                     = "/opt/vault/tls/vault-key.pem"
  tls_client_ca_file               = "/opt/vault/tls/vault-ca.pem"
  x_forwarded_for_authorized_addrs = ${load_balancer_subnet_cidrs}
}
seal "awskms" {
  region     = "${region}"
  kms_key_id = "${kms_key_arn}"
}
telemetry {
  prometheus_retention_time = "60s"
  disable_hostname          = true
}
${vault_enterprise_license_config}
EOF

${snapshot_config}
```

### Replacing the Enterprise Binary with OSS

It is possible to downgrade from Enterprise to OSS, but has to be done very specifically.  If you have not read the section above that points out Enterprise-only features, please read it now.

**NOTE: Please read all instructions carefully before taking any action.  This process should be completed rather quickly, as it essentially takes Vault down to a single node cluster, but the Vault configs likely have voting quorum set to 3 or 5, so leader election can fail during this time, causing outages.**

_**MAKE SURE TO TAKE A BACKUP BEFORE STARTING!!!**_

```console
# On the active / leader node
vault login -method=ldap username=jsmith
CURRENT_DATE=$(date +%Y-%m-%d-%H-%M-%S)
vault operator raft snapshot save > "pre_oss_migration_${CURRENT_DATE}Z.snap"
aws s3 cp "pre_oss_migration_${CURRENT_DATE}Z.snap" s3://<backups-bucket>
```

1. Log into AWS and suspend the processes on the autoscaling group so that nodes are not replaced when unhealthy or terminated (you can just suspend all the processes, like Terminate, Launch, Replace Unhealthy, etc.), essentially locking the ASG to the current nodes.  We are going to be stopping and starting Vault, and it could fail health checks during this time, so we do not want nodes to be replaced while we are working on them.
2. SSH into all 3 (or however many you deployed) Vault Enterprise nodes.
3. Use `vault status` on each node to identify the standby nodes and active node.
4. On all nodes, download the vault OSS binary using `wget` or `curl` from releases.hashicorp.com.  **MAKE SURE TO MATCH THE OS ARCH AND RUNNING ENTERPRISE VERSION!!!**  Make sure you are using the `arm64` binary if running on Graviton!

        VERSION="1.15.4-1"
        ARCH=$(dpkg --print-architecture)
        wget "https://releases.hashicorp.com/vault/${VERSION}/vault_${VERSION}_linux_${ARCH}.zip" -O vault.zip

5. Unzip the binaries, but do not move them yet.

        unzip vault.zip

6. On all servers, update the server config file (module defaults to `/etc/vault.d/vault.hcl`) and make sure to _**REMOVE**_ the `license_path` line from the file. Save and exit the file.  This is safe to do with Vault still running because this file is loaded at runtime.
7. **ON THE STANDBY NODES ONLY:** Stop vault with `systemctl stop vault`. This will leave you with a single node cluster, and as long as that node does not attempt a leader election during this time window, Vault should continue to function properly.
8. **ON ALL NODES:** Replace the binary, making sure to confirm its location first, then make sure to set MLOCK.

        $ which vault
        /usr/bin/vault
        $ mv vault /usr/bin/vault
        $ sudo setcap cap_ipc_lock=+ep $(readlink -f $(which vault))

9. **ON THE ACTIVE NODE ONLY:** Restart the vault process to load the new binary and new config that does not have a `license_path` parameter.  **IF YOU DO NOT REMOVE THE `license_path` PARAMETER VAULT OSS WILL FAIL TO START!!!**

        # Validate that license_path is not in the config file
        cat /etc/vault.d/vault.hcl | grep 'license_path'
        systemctl restart vault
        vault status

10. After restarting vault on the active node, the `vault status` command should be run to confirm the version that is running and that Vault is unsealed and healthy. If it is not, continue to proceed, as Vault may require a leader election or quorum vote to return to a health status.
11. **ON THE STANDBY NODES:** Start vault with

        systemctl start vault
        vault status

12. Confirm that the version running is OSS via `vault status`.
13. On any node, log into vault and confirm the cluster members with the operator command:

        vault operator raft list-peers

14. The migration is nearly complete.  Unlock the autoscaling group in AWS by removing the suspended processes.  Update the terraform to match your configs (below) and run `terraform apply`.  This will update the `user_data` in the launch template and roll the nodes, so that any future updates or node replacement will function properly and use the OSS binary without a `license_path` parameter:

        vault_binary  = "vault"
        vault_version = "1.15.4-1" # or whatever version, was likely "1.15.4-1+ent" before this work

15. **WARNING!!!** The user data changes we made above *SHOULD* configure Vault to take daily snapshots.  However it is always a good idea to log into the Leader node after Terraform has rolled the nodes and Vault is healthy and run the backup script once manually to validate its functionality.

Thats it--the cluster should now be running Vault OSS.
