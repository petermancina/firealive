// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Cloud & IaC Templates: AWS CloudFormation (R3k C14, Cloud Mode B5h)
//
// AWS-only. Provisions FireAlive on a CONFIDENTIAL EC2 instance: AMD SEV-SNP
// memory encryption (CpuOptions.AmdSevSnp) plus NitroTPM, which presents to the
// guest as a TPM 2.0 hardware root of trust. Cloud mode REQUIRES confidential
// computing and is attested at boot, so the managed-container path (ECS Fargate)
// is intentionally not emitted. The generator pre-validates the provider, but
// the template double-checks defensively.
//
// Secrets live in Secrets Manager and are fetched at boot by the instance role;
// they are never placed in user_data in cleartext, because the confidential-VM
// model assumes the provider can read instance metadata but not guest memory.
//
// Content is built as an array of lines joined by NL (a literal newline) with
// plain double quotes inside single-quoted JS strings, so the template carries
// no backslash escapes.
// ═══════════════════════════════════════════════════════════════════════════════

const NL = String.fromCharCode(10);

function render(snapshot, provider) {
  if (provider !== 'aws') {
    throw new Error(`cloudformation template: AWS-only, got '${provider}'`);
  }
  const yaml = [
    'AWSTemplateFormatVersion: "2010-09-09"',
    'Description: FireAlive deployment (confidential EC2 with SEV-SNP + NitroTPM + Secrets Manager)',
    '',
    'Parameters:',
    '  Tier1EncryptionKey:',
    '    Type: String',
    '    NoEcho: true',
    '    Description: 32-byte hex KEK for the v2 backup engine',
    '  JwtSecret:',
    '    Type: String',
    '    NoEcho: true',
    '    Description: JWT signing secret (>=16 random chars)',
    '  InstanceSize:',
    '    Type: String',
    '    Default: m6a.large',
    '    Description: SEV-SNP-capable instance type (m6a / c6a / r6a)',
    '  ImageId:',
    '    Type: AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>',
    '    Default: /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64',
    '    Description: UEFI AMI with TPM 2.0 (NitroTPM); default resolves the latest AL2023',
    '',
    'Resources:',
    '  Tier1KeySecret:',
    '    Type: AWS::SecretsManager::Secret',
    '    Properties:',
    '      Name: firealive/tier1-encryption-key',
    '      SecretString: !Ref Tier1EncryptionKey',
    '',
    '  JwtSecretRes:',
    '    Type: AWS::SecretsManager::Secret',
    '    Properties:',
    '      Name: firealive/jwt-secret',
    '      SecretString: !Ref JwtSecret',
    '',
    '  InstanceRole:',
    '    Type: AWS::IAM::Role',
    '    Properties:',
    '      AssumeRolePolicyDocument:',
    '        Version: "2012-10-17"',
    '        Statement:',
    '          - Effect: Allow',
    '            Principal: { Service: ec2.amazonaws.com }',
    '            Action: sts:AssumeRole',
    '      Policies:',
    '        - PolicyName: read-firealive-secrets',
    '          PolicyDocument:',
    '            Version: "2012-10-17"',
    '            Statement:',
    '              - Effect: Allow',
    '                Action: secretsmanager:GetSecretValue',
    '                Resource:',
    '                  - !Ref Tier1KeySecret',
    '                  - !Ref JwtSecretRes',
    '',
    '  InstanceProfile:',
    '    Type: AWS::IAM::InstanceProfile',
    '    Properties:',
    '      Roles:',
    '        - !Ref InstanceRole',
    '',
    '  # AMD SEV-SNP confidential instance with NitroTPM (TPM 2.0 root of trust).',
    '  # On-demand only: cloud mode refuses spot / autoscaled / ephemeral-fleet',
    '  # instances, so do NOT place this in an Auto Scaling group or Spot request.',
    '  Server:',
    '    Type: AWS::EC2::Instance',
    '    Properties:',
    '      ImageId: !Ref ImageId',
    '      InstanceType: !Ref InstanceSize',
    '      IamInstanceProfile: !Ref InstanceProfile',
    '      CpuOptions:',
    '        AmdSevSnp: enabled',
    '      MetadataOptions:',
    '        HttpTokens: required',
    '      Tags:',
    '        - Key: Name',
    '          Value: firealive',
    '        - Key: DeploymentMode',
    '          Value: cloud',
    '      UserData:',
    '        Fn::Base64: !Sub |',
    '          #cloud-config',
    '          runcmd:',
    '            - mkdir -p /etc/firealive',
    '            - TIER1=$(aws secretsmanager get-secret-value --secret-id firealive/tier1-encryption-key --query SecretString --output text)',
    '            - JWT=$(aws secretsmanager get-secret-value --secret-id firealive/jwt-secret --query SecretString --output text)',
    '            - umask 077',
    '            - echo "TIER1_ENCRYPTION_KEY=$TIER1" > /etc/firealive/.env',
    '            - echo "JWT_SECRET=$JWT" >> /etc/firealive/.env',
    '            - echo "FIREALIVE_DEPLOYMENT_MODE=cloud" >> /etc/firealive/.env',
    '            - systemctl enable --now firealive',
    '',
    'Outputs:',
    '  Endpoint:',
    '    Value: !Sub "https://${Server.PublicIp}:3000"',
    '  Note:',
    '    Value: "Production deployment also needs a VPC, subnet, security group, an EBS data volume or RDS, and Docker preinstalled in the AMI"',
    '',
    `# Snapshot at generation: users=${snapshot.users.total}, db_size_bytes=${snapshot.data.db_size_bytes}`,
    '',
  ].join(NL);
  return {
    files: [{ path: 'firealive.yaml', content: yaml }],
  };
}

module.exports = { render };
