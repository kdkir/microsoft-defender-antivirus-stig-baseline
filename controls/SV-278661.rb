control 'SV-278661' do
  title 'Microsoft Defender AV must enable the file hash computation feature.'
  desc 'This policy drives the ability to enforce Indicators of Compromise (IoC) by using file hash allow/block indicators.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> MpEngine >> Enable file hash computation feature is set to "Enabled"; otherwise, this is a finding.

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\MpEngine

Criteria: If the value "EnableFileHashComputation" is REG_DWORD = 1, this is not a finding.

If the value is 0, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> MpEngine >>Enable file hash computation feature to "Enabled".

Click "OK".

Click "Apply".'
  impact 0.5
  tag check_id: 'C-83195r1144058_chk'
  tag severity: 'medium'
  tag gid: 'V-278661'
  tag rid: 'SV-278661r1144059_rule'
  tag stig_id: 'WNDF-AV-000057'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-83100r1133674_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']

  registry_path = 'HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\MpEngine'

  describe registry_key(registry_path) do
    its('EnableFileHashComputation') { should eq 1 }
  end

end
