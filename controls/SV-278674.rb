control 'SV-278674' do
  title 'Microsoft Defender AV must enable EDR in block mode.'
  desc 'EDR in block mode allows Microsoft Defender Antivirus to take actions on post-breach, behavioral EDR detections. EDR in block mode is integrated with threat and vulnerability management capabilities.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Features >> Enable EDR in block mode is set to "Enabled"; otherwise, this is a finding.

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Features

Criteria: If the value "PassiveRemediation" is REG_DWORD = 1, this is not a finding.

If the value is 0, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Features >> Enable EDR in block mode to "Enabled".

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83208r1144070_chk'
  tag severity: 'medium'
  tag gid: 'V-278674'
  tag rid: 'SV-278674r1144071_rule'
  tag stig_id: 'WNDF-AV-000070'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-83113r1133713_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
