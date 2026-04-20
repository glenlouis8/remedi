'use client';

import Link from 'next/link';
import { ShieldCheck, ArrowLeft, CheckCircle, Trash2, Lock, Eye } from 'lucide-react';

const AUDIT_PERMISSIONS = [
  { action: 'sts:GetCallerIdentity',            why: 'Verifies the credentials are valid before scanning' },
  { action: 'iam:ListUsers',                    why: 'Lists all IAM users in the account' },
  { action: 'iam:ListAttachedUserPolicies',      why: 'Checks which policies are attached to each user' },
  { action: 'iam:ListUserPolicies',             why: 'Checks for inline policies on each user' },
  { action: 'iam:ListAttachedRolePolicies',     why: 'Checks policies attached to Lambda execution roles' },
  { action: 'iam:ListRolePolicies',             why: 'Checks for inline policies on roles' },
  { action: 'iam:GetRolePolicy',                why: 'Reads the content of inline role policies' },
  { action: 's3:ListAllMyBuckets',              why: 'Lists all S3 buckets in the account' },
  { action: 's3:GetBucketPublicAccessBlock',    why: 'Checks if public access is blocked on each bucket' },
  { action: 's3:GetBucketAcl',                 why: 'Checks bucket ACL for public grants' },
  { action: 's3:GetBucketPolicy',              why: 'Checks bucket policy for public read rules' },
  { action: 'ec2:DescribeVpcs',                why: 'Lists all VPCs in the account' },
  { action: 'ec2:DescribeFlowLogs',            why: 'Checks if VPC Flow Logs are enabled' },
  { action: 'ec2:DescribeSecurityGroups',      why: 'Lists all security groups and their inbound rules' },
  { action: 'ec2:DescribeInstances',           why: 'Lists all EC2 instances and their metadata settings' },
  { action: 'rds:DescribeDBInstances',         why: 'Lists all RDS databases and checks public access' },
  { action: 'lambda:ListFunctions',            why: 'Lists all Lambda functions' },
  { action: 'lambda:GetFunction',              why: 'Gets the execution role for each Lambda function' },
  { action: 'cloudtrail:DescribeTrails',       why: 'Lists all CloudTrail trails' },
  { action: 'cloudtrail:GetTrailStatus',       why: 'Checks if logging is active on each trail' },
  { action: 'logs:DescribeLogGroups',          why: 'Checks for existing CloudWatch log groups' },
];

const REMEDIATION_PERMISSIONS = [
  { action: 'iam:DetachUserPolicy',            why: 'Removes overpermissioned policies from IAM users' },
  { action: 'iam:DetachRolePolicy',            why: 'Removes overpermissioned policies from Lambda roles' },
  { action: 'iam:AttachRolePolicy',            why: 'Attaches a least-privilege policy to Lambda roles' },
  { action: 'iam:DeleteRolePolicy',            why: 'Removes wildcard inline policies from Lambda roles' },
  { action: 'iam:CreateRole',                  why: 'Creates a role for VPC Flow Logs to write to CloudWatch' },
  { action: 'iam:PutRolePolicy',               why: 'Grants the Flow Logs role permission to write logs' },
  { action: 'iam:PassRole',                    why: 'Allows passing the Flow Logs role to the VPC service' },
  { action: 's3:PutPublicAccessBlock',         why: 'Blocks all public access on exposed S3 buckets' },
  { action: 's3:CreateBucket',                 why: 'Creates an S3 bucket to store CloudTrail logs' },
  { action: 's3:PutBucketPolicy',              why: 'Sets the policy on the CloudTrail log bucket' },
  { action: 'ec2:CreateFlowLogs',              why: 'Enables VPC Flow Logs on unmonitored VPCs' },
  { action: 'ec2:RevokeSecurityGroupIngress',  why: 'Removes 0.0.0.0/0 inbound rules from security groups' },
  { action: 'ec2:ModifyInstanceMetadataOptions', why: 'Enforces IMDSv2 on EC2 instances (blocks IMDSv1)' },
  { action: 'ec2:StopInstances',               why: 'Quarantines EC2 instances with unencrypted root volumes' },
  { action: 'rds:ModifyDBInstance',            why: 'Disables public accessibility on exposed RDS databases' },
  { action: 'cloudtrail:CreateTrail',          why: 'Creates a CloudTrail trail if none exists' },
  { action: 'cloudtrail:StartLogging',         why: 'Enables logging on an existing but inactive trail' },
  { action: 'logs:CreateLogGroup',             why: 'Creates a CloudWatch log group for VPC Flow Logs' },
];

export default function SetupDetailsPage() {
  return (
    <div className="min-h-screen bg-[#09090b] text-white px-6 py-12" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');`}</style>

      {/* Grid background */}
      <div className="fixed inset-0 pointer-events-none" style={{
        backgroundImage: 'linear-gradient(rgba(139,92,246,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(139,92,246,0.04) 1px, transparent 1px)',
        backgroundSize: '40px 40px'
      }} />

      <div className="relative z-10 max-w-2xl mx-auto">

        {/* Header */}
        <div className="flex items-center justify-between mb-10">
          <Link href="/dashboard" className="flex items-center gap-2 hover:opacity-80 transition-opacity">
            <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ background: 'rgba(139,92,246,0.15)', border: '1px solid rgba(139,92,246,0.25)' }}>
              <ShieldCheck size={15} className="text-violet-400" />
            </div>
            <span className="font-semibold tracking-tight text-white">Remedi</span>
          </Link>
          <Link href="/onboarding" className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-300 transition-colors">
            <ArrowLeft size={13} /> Back to setup
          </Link>
        </div>

        <h1 className="text-2xl font-bold mb-2 text-white">What does the automatic setup create?</h1>
        <p className="text-slate-400 text-sm mb-4">
          When you click "Launch AWS setup automatically", a CloudFormation stack creates three things in your AWS account. Here's exactly what gets created and why.
        </p>

        {/* Safety banner */}
        <div className="rounded-xl p-4 mb-8" style={{ background: 'rgba(139,92,246,0.06)', border: '1px solid rgba(139,92,246,0.15)' }}>
          <p className="text-sm font-semibold text-violet-300 mb-2">This setup is designed to be safe and fully reversible.</p>
          <ul className="space-y-1.5">
            {[
              { label: 'Minimum permissions only.', body: 'The policy grants exactly what Remedi needs — no wildcards, no admin access, no access to your data.' },
              { label: 'Remedi never reads your data.', body: 'It only reads metadata — bucket names, security group rules, instance settings. It cannot read files inside S3 or database contents.' },
              { label: 'Fixes only run with your approval.', body: 'Remedi scans automatically but nothing is changed until you explicitly click "Approve".' },
              { label: 'Revoke access anytime in one click.', body: 'Delete the CloudFormation stack and the IAM user, policy, and access key are all gone immediately. Remedi also deletes your credentials from its database the moment you sign out.' },
              { label: 'Credentials are encrypted at rest.', body: 'Remedi stores your access key encrypted with AES-256. They are never logged or shared.' },
            ].map(({ label, body }) => (
              <li key={label} className="flex items-start gap-2 text-xs text-violet-200/70">
                <CheckCircle size={13} className="text-violet-500 shrink-0 mt-0.5" />
                <span><strong className="text-violet-200">{label}</strong> {body}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* What gets created */}
        <div className="space-y-3 mb-10">
          {[
            {
              title: <>IAM User — <code className="text-violet-400" style={{ fontFamily: "'JetBrains Mono', monospace" }}>remedi-agent</code></>,
              body: 'A dedicated IAM user created solely for Remedi. Using a separate user means you can delete it at any time to immediately revoke all access — no need to touch your main credentials.',
            },
            {
              title: <>Custom IAM Policy — <code className="text-violet-400" style={{ fontFamily: "'JetBrains Mono', monospace" }}>RemediAgentPolicy</code></>,
              body: <>A least-privilege policy with exactly the permissions Remedi needs — nothing more. Unlike <code className="px-1 rounded text-slate-300" style={{ background: 'rgba(255,255,255,0.05)', fontFamily: "'JetBrains Mono', monospace" }}>AdministratorAccess</code>, this policy cannot delete databases, access Secrets Manager, touch billing, or read the contents of your S3 buckets.</>,
            },
            {
              title: 'Access Key',
              body: <>An access key and secret key for the <code className="px-1 rounded text-slate-300" style={{ background: 'rgba(255,255,255,0.05)', fontFamily: "'JetBrains Mono', monospace" }}>remedi-agent</code> user. These appear in the CloudFormation stack's <strong className="text-slate-300">Outputs</strong> tab. Copy them into Remedi. Deleting the stack deletes the key.</>,
            },
          ].map(({ title, body }, i) => (
            <div key={i} className="rounded-xl p-5" style={{ background: 'rgba(14,14,18,0.8)', border: '1px solid rgba(255,255,255,0.07)' }}>
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle size={15} className="text-violet-500 shrink-0" />
                <p className="font-semibold text-sm text-white">{title}</p>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">{body}</p>
            </div>
          ))}
        </div>

        {/* Audit permissions */}
        <h2 className="text-base font-semibold text-white mb-1">Read-only permissions <span className="text-slate-500 font-normal text-sm">({AUDIT_PERMISSIONS.length})</span></h2>
        <p className="text-xs text-slate-500 mb-3">Used during scanning. These permissions cannot change anything in your account.</p>
        <div className="rounded-xl overflow-hidden mb-6" style={{ background: 'rgba(14,14,18,0.8)', border: '1px solid rgba(255,255,255,0.07)' }}>
          <div className="divide-y" style={{ borderColor: 'rgba(255,255,255,0.04)' }}>
            {AUDIT_PERMISSIONS.map(p => (
              <div key={p.action} className="flex items-start gap-3 px-5 py-3">
                <Eye size={13} className="text-slate-600 shrink-0 mt-0.5" />
                <code className="text-xs text-violet-300/80 w-64 shrink-0" style={{ fontFamily: "'JetBrains Mono', monospace" }}>{p.action}</code>
                <p className="text-xs text-slate-500">{p.why}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Remediation permissions */}
        <h2 className="text-base font-semibold text-white mb-1">Remediation permissions <span className="text-slate-500 font-normal text-sm">({REMEDIATION_PERMISSIONS.length})</span></h2>
        <p className="text-xs text-slate-500 mb-3">Used only after you explicitly approve fixes. Each action maps to a specific vulnerability Remedi can fix.</p>
        <div className="rounded-xl overflow-hidden mb-8" style={{ background: 'rgba(14,14,18,0.8)', border: '1px solid rgba(255,255,255,0.07)' }}>
          <div className="divide-y" style={{ borderColor: 'rgba(255,255,255,0.04)' }}>
            {REMEDIATION_PERMISSIONS.map(p => (
              <div key={p.action} className="flex items-start gap-3 px-5 py-3">
                <Lock size={13} className="text-slate-600 shrink-0 mt-0.5" />
                <code className="text-xs text-violet-300/80 w-64 shrink-0" style={{ fontFamily: "'JetBrains Mono', monospace" }}>{p.action}</code>
                <p className="text-xs text-slate-500">{p.why}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Deleting */}
        <div className="rounded-xl p-5 mb-8" style={{ background: 'rgba(14,14,18,0.8)', border: '1px solid rgba(255,255,255,0.07)' }}>
          <div className="flex items-center gap-2 mb-2">
            <Trash2 size={15} className="text-red-400 shrink-0" />
            <p className="font-semibold text-sm text-white">How to revoke access</p>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Go to <strong className="text-slate-300">AWS Console → CloudFormation → Stacks → remedi-agent → Delete</strong>. This deletes the IAM user, the policy, and the access key in one click. All access is immediately revoked. Remedi also automatically deletes your credentials from its database when you sign out.
          </p>
        </div>

        <Link
          href="/onboarding"
          className="inline-flex items-center gap-2 bg-violet-500 hover:bg-violet-400 text-white font-semibold text-sm px-5 py-2.5 rounded-lg transition-colors"
        >
          <ArrowLeft size={14} /> Back to setup
        </Link>

      </div>
    </div>
  );
}
