// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// A small rule-coverage snapshot in the shape scripts/build-rule-coverage-snapshot.mjs
// writes (src/assets/data/rule-coverage-snapshot.json): three techniques per source,
// two rules each, copied from the real file at the pins it records. Specs flush it
// for the asset request instead of loading the 1 MB file.
import type { RuleCoverageKey, RuleCoverageSource } from '../services/rule-coverage-snapshot.service';

export const RULE_COVERAGE_FIXTURE: { generated: string; sources: Record<RuleCoverageKey, RuleCoverageSource> } =
{
    "generated": "2026-10-21",
    "sources": {
      "elastic": {
        "owner": "elastic",
        "repo": "detection-rules",
        "branch": "main",
        "sha": "7115bb0ab06c11c7994486ffe2bc0dc801ad8502",
        "commitDate": "2026-10-21T07:09:07Z",
        "licence": "Elastic-2.0",
        "ruleCount": 2131,
        "techniqueCount": 3,
        "techniques": {
          "T1059": {
            "count": 323,
            "rules": [
              {
                "name": "AWS Batch Job Submitted with Container Override by Unusual Identity",
                "path": "rules/integrations/aws/execution_batch_job_submitted_container_override_unusual_identity.toml"
              },
              {
                "name": "AWS Bedrock High Risk Filesystem or Execution Tool Invocation",
                "path": "rules/integrations/aws_bedrock/execution_bedrock_high_risk_tool_invocation.toml"
              }
            ]
          },
          "T1059.001": {
            "count": 111,
            "rules": [
              {
                "name": "AWS SSM Session Manager Child Process Execution",
                "path": "rules/cross-platform/execution_aws_ssm_session_manager_child_process.toml"
              },
              {
                "name": "AWS SSM `SendCommand` with Run Shell Command Parameters",
                "path": "rules/cross-platform/execution_aws_ssm_sendcommand_with_command_parameters.toml"
              }
            ]
          },
          "T1114": {
            "count": 11,
            "rules": [
              {
                "name": "Exchange Mailbox Export via PowerShell",
                "path": "rules/windows/collection_mailbox_export_winlog.toml"
              },
              {
                "name": "Exporting Exchange Mailbox via PowerShell",
                "path": "rules/windows/collection_email_powershell_exchange_mailbox.toml"
              }
            ]
          }
        }
      },
      "splunk": {
        "owner": "splunk",
        "repo": "security_content",
        "branch": "develop",
        "sha": "678e76c5f36f6fadd93a1eaa0d82c1dbe273c486",
        "commitDate": "2026-10-20T23:33:59Z",
        "licence": "Apache-2.0",
        "ruleCount": 2169,
        "techniqueCount": 3,
        "techniques": {
          "T1059": {
            "count": 165,
            "rules": [
              {
                "name": "CMD Carry Out String Command Parameter",
                "path": "detections/endpoint/cmd_carry_out_string_command_parameter.yml"
              },
              {
                "name": "CMD Echo Pipe - Escalation",
                "path": "detections/endpoint/cmd_echo_pipe___escalation.yml"
              }
            ]
          },
          "T1059.001": {
            "count": 69,
            "rules": [
              {
                "name": "Cisco Secure Firewall - Communication Over Suspicious Ports",
                "path": "detections/network/cisco_secure_firewall___communication_over_suspicious_ports.yml"
              },
              {
                "name": "Cisco Secure Firewall - Veeam CVE-2023-27532 Exploitation Activity",
                "path": "detections/network/cisco_secure_firewall___veeam_cve_2023_27532_exploitation_activity.yml"
              }
            ]
          },
          "T1560.001": {
            "count": 4,
            "rules": [
              {
                "name": "7zip CommandLine To SMB Share Path",
                "path": "detections/endpoint/7zip_commandline_to_smb_share_path.yml"
              },
              {
                "name": "Anomalous usage of 7zip",
                "path": "detections/endpoint/anomalous_usage_of_7zip.yml"
              }
            ]
          }
        }
      },
      "mdecrevoisier": {
        "owner": "mdecrevoisier",
        "repo": "SIGMA-detection-rules",
        "branch": "main",
        "sha": "d61408af8769c74c96296b7ccc92d4bc3abb15af",
        "commitDate": "2026-05-20T23:07:47Z",
        "licence": "CC0-1.0",
        "ruleCount": 353,
        "techniqueCount": 3,
        "techniques": {
          "T1059": {
            "count": 7,
            "rules": [
              {
                "name": "Encoded PowerShell payload deployed (PowerShell)",
                "path": "windows-os/win-os-payload encoded PowerShell deployed (PowerShell).yaml"
              },
              {
                "name": "Encoded PowerShell payload deployed via process execution",
                "path": "windows-os/win-os-payload encoded PowerShell deployed (command).yaml"
              }
            ]
          },
          "T1059.001": {
            "count": 4,
            "rules": [
              {
                "name": "Encoded PowerShell payload deployed (PowerShell)",
                "path": "windows-os/win-os-payload encoded PowerShell deployed (PowerShell).yaml"
              },
              {
                "name": "Payload downloaded via PowerShell",
                "path": "windows-os/win-os-payload download (PowerShell).yaml"
              }
            ]
          },
          "T1484.002": {
            "count": 1,
            "rules": [
              {
                "name": "Active Directory federated trust added",
                "path": "cloud-azure/azure-active-directory-new federated trust added.yaml"
              }
            ]
          }
        }
      }
    }
  };
