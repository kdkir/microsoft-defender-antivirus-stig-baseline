control 'SV-278672' do
  title 'Microsoft Defender AV must enable network protection to be configured into block or audit mode on Windows Server.'
  desc "Microsoft's Exploit Guard comprises several techniques to defend against phishing attacks and malware. These include controlled folder access, attack surface reduction, and network protection."
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Network Protection >> This settings controls whether Network Protection is allowed to be configured into block or audit mode on Windows Server is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection

Criteria: If the value "AllowNetworkProtectionOnWinServer" is REG_DWORD = 1, this is not a finding.

If the value is 0, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Network Protection >> This settings controls whether Network Protection is allowed to be configured into block or audit mode on Windows Server to "Enabled".

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83206r1144066_chk'
  tag severity: 'medium'
  tag gid: 'V-278672'
  tag rid: 'SV-278672r1144067_rule'
  tag stig_id: 'WNDF-AV-000068'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-83111r1133707_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
