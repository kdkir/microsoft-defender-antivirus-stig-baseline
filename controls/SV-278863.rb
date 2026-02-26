control 'SV-278863' do
  title 'Microsoft Defender AV must set cloud protection level to High.'
  desc 'Cloud protection in Microsoft Defender Antivirus delivers accurate, real-time, and intelligent protection. Cloud protection should be enabled by default.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> MpEngine >> Select cloud protection level is set to "Enabled". Verify the policy value for "Select cloud blocking level" is set to "High blocking level"; otherwise, this is a finding.

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\MpEngine

Criteria: If the value "MpCloudBlockLevel" is REG_DWORD = 2, this is not a finding.

If the value is other than 2, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> MpEngine >> Select cloud protection level to "Enabled".

Set policy value "Select cloud blocking level" to "High blocking level".

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83397r1144084_chk'
  tag severity: 'medium'
  tag gid: 'V-278863'
  tag rid: 'SV-278863r1144086_rule'
  tag stig_id: 'WNDF-AV-000073'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-83302r1144085_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
